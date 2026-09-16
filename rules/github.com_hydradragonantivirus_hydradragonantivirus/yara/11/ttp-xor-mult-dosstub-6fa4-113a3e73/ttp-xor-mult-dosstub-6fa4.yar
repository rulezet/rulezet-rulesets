rule TTP_XOR_MULT_DOSStub_6fa4 {
  strings:
    $key_6fa4 = { 3b cc [2] 4f d4 [2] 08 d6 [2] 4f c7 [2] 01 cb [2] 0d c1 [2] 1a ca [2] 01 84 [2] 3c }

  condition:
    any of them
}