rule TTP_XOR_MULT_DOSStub_0967 {
  strings:
    $key_0967 = { 5d 0f [2] 29 17 [2] 6e 15 [2] 29 04 [2] 67 08 [2] 6b 02 [2] 7c 09 [2] 67 47 [2] 5a }

  condition:
    any of them
}