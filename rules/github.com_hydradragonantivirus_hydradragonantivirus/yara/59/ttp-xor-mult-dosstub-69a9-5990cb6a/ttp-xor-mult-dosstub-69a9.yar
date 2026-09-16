rule TTP_XOR_MULT_DOSStub_69a9 {
  strings:
    $key_69a9 = { 3d c1 [2] 49 d9 [2] 0e db [2] 49 ca [2] 07 c6 [2] 0b cc [2] 1c c7 [2] 07 89 [2] 3a }

  condition:
    any of them
}