rule TTP_XOR_MULT_DOSStub_1967 {
  strings:
    $key_1967 = { 4d 0f [2] 39 17 [2] 7e 15 [2] 39 04 [2] 77 08 [2] 7b 02 [2] 6c 09 [2] 77 47 [2] 4a }

  condition:
    any of them
}