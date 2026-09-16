rule TTP_XOR_MULT_DOSStub_4846 {
  strings:
    $key_4846 = { 1c 2e [2] 68 36 [2] 2f 34 [2] 68 25 [2] 26 29 [2] 2a 23 [2] 3d 28 [2] 26 66 [2] 1b }

  condition:
    any of them
}