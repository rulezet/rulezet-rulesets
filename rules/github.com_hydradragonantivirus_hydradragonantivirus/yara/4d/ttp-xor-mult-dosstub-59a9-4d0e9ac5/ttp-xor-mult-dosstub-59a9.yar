rule TTP_XOR_MULT_DOSStub_59a9 {
  strings:
    $key_59a9 = { 0d c1 [2] 79 d9 [2] 3e db [2] 79 ca [2] 37 c6 [2] 3b cc [2] 2c c7 [2] 37 89 [2] 0a }

  condition:
    any of them
}