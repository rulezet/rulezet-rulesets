rule TTP_XOR_MULT_DOSStub_3a41 {
  strings:
    $key_3a41 = { 6e 29 [2] 1a 31 [2] 5d 33 [2] 1a 22 [2] 54 2e [2] 58 24 [2] 4f 2f [2] 54 61 [2] 69 }

  condition:
    any of them
}