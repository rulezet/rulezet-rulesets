rule TTP_XOR_MULT_DOSStub_18a9 {
  strings:
    $key_18a9 = { 4c c1 [2] 38 d9 [2] 7f db [2] 38 ca [2] 76 c6 [2] 7a cc [2] 6d c7 [2] 76 89 [2] 4b }

  condition:
    any of them
}