rule TTP_XOR_MULT_DOSStub_3a60 {
  strings:
    $key_3a60 = { 6e 08 [2] 1a 10 [2] 5d 12 [2] 1a 03 [2] 54 0f [2] 58 05 [2] 4f 0e [2] 54 40 [2] 69 }

  condition:
    any of them
}