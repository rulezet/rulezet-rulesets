rule TTP_XOR_MULT_DOSStub_3a51 {
  strings:
    $key_3a51 = { 6e 39 [2] 1a 21 [2] 5d 23 [2] 1a 32 [2] 54 3e [2] 58 34 [2] 4f 3f [2] 54 71 [2] 69 }

  condition:
    any of them
}