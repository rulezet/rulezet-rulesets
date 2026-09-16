rule TTP_XOR_MULT_DOSStub_3a01 {
  strings:
    $key_3a01 = { 6e 69 [2] 1a 71 [2] 5d 73 [2] 1a 62 [2] 54 6e [2] 58 64 [2] 4f 6f [2] 54 21 [2] 69 }

  condition:
    any of them
}