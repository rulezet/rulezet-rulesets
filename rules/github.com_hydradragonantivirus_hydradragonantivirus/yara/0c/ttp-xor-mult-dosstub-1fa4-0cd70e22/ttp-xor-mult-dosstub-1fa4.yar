rule TTP_XOR_MULT_DOSStub_1fa4 {
  strings:
    $key_1fa4 = { 4b cc [2] 3f d4 [2] 78 d6 [2] 3f c7 [2] 71 cb [2] 7d c1 [2] 6a ca [2] 71 84 [2] 4c }

  condition:
    any of them
}