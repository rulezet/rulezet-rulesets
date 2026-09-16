rule TTP_XOR_MULT_DOSStub_2a66 {
  strings:
    $key_2a66 = { 7e 0e [2] 0a 16 [2] 4d 14 [2] 0a 05 [2] 44 09 [2] 48 03 [2] 5f 08 [2] 44 46 [2] 79 }

  condition:
    any of them
}