rule TTP_XOR_MULT_DOSStub_0fa4 {
  strings:
    $key_0fa4 = { 5b cc [2] 2f d4 [2] 68 d6 [2] 2f c7 [2] 61 cb [2] 6d c1 [2] 7a ca [2] 61 84 [2] 5c }

  condition:
    any of them
}