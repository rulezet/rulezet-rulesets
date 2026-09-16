rule TTP_XOR_MULT_DOSStub_7fa4 {
  strings:
    $key_7fa4 = { 2b cc [2] 5f d4 [2] 18 d6 [2] 5f c7 [2] 11 cb [2] 1d c1 [2] 0a ca [2] 11 84 [2] 2c }

  condition:
    any of them
}