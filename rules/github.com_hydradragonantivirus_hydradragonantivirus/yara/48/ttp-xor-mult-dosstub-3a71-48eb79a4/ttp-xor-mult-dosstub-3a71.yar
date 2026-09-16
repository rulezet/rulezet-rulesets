rule TTP_XOR_MULT_DOSStub_3a71 {
  strings:
    $key_3a71 = { 6e 19 [2] 1a 01 [2] 5d 03 [2] 1a 12 [2] 54 1e [2] 58 14 [2] 4f 1f [2] 54 51 [2] 69 }

  condition:
    any of them
}