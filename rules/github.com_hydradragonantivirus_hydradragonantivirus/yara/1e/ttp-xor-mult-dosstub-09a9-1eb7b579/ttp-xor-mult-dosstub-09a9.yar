rule TTP_XOR_MULT_DOSStub_09a9 {
  strings:
    $key_09a9 = { 5d c1 [2] 29 d9 [2] 6e db [2] 29 ca [2] 67 c6 [2] 6b cc [2] 7c c7 [2] 67 89 [2] 5a }

  condition:
    any of them
}