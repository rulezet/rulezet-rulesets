rule TTP_XOR_MULT_DOSStub_08a9 {
  strings:
    $key_08a9 = { 5c c1 [2] 28 d9 [2] 6f db [2] 28 ca [2] 66 c6 [2] 6a cc [2] 7d c7 [2] 66 89 [2] 5b }

  condition:
    any of them
}