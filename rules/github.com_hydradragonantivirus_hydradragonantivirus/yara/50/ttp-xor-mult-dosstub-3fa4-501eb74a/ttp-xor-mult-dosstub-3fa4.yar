rule TTP_XOR_MULT_DOSStub_3fa4 {
  strings:
    $key_3fa4 = { 6b cc [2] 1f d4 [2] 58 d6 [2] 1f c7 [2] 51 cb [2] 5d c1 [2] 4a ca [2] 51 84 [2] 6c }

  condition:
    any of them
}