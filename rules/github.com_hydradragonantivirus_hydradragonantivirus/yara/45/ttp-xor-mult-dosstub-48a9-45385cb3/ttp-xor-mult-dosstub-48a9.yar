rule TTP_XOR_MULT_DOSStub_48a9 {
  strings:
    $key_48a9 = { 1c c1 [2] 68 d9 [2] 2f db [2] 68 ca [2] 26 c6 [2] 2a cc [2] 3d c7 [2] 26 89 [2] 1b }

  condition:
    any of them
}