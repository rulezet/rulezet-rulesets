rule TTP_XOR_MULT_DOSStub_79a9 {
  strings:
    $key_79a9 = { 2d c1 [2] 59 d9 [2] 1e db [2] 59 ca [2] 17 c6 [2] 1b cc [2] 0c c7 [2] 17 89 [2] 2a }

  condition:
    any of them
}