rule TTP_XOR_MULT_DOSStub_68a9 {
  strings:
    $key_68a9 = { 3c c1 [2] 48 d9 [2] 0f db [2] 48 ca [2] 06 c6 [2] 0a cc [2] 1d c7 [2] 06 89 [2] 3b }

  condition:
    any of them
}