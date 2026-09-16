rule TTP_XOR_MULT_DOSStub_4a06 {
  strings:
    $key_4a06 = { 1e 6e [2] 6a 76 [2] 2d 74 [2] 6a 65 [2] 24 69 [2] 28 63 [2] 3f 68 [2] 24 26 [2] 19 }

  condition:
    any of them
}