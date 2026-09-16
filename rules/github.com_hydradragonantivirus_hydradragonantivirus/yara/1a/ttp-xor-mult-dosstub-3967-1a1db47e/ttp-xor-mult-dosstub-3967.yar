rule TTP_XOR_MULT_DOSStub_3967 {
  strings:
    $key_3967 = { 6d 0f [2] 19 17 [2] 5e 15 [2] 19 04 [2] 57 08 [2] 5b 02 [2] 4c 09 [2] 57 47 [2] 6a }

  condition:
    any of them
}