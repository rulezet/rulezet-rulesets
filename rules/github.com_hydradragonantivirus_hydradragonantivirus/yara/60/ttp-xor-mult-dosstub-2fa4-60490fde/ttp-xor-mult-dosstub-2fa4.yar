rule TTP_XOR_MULT_DOSStub_2fa4 {
  strings:
    $key_2fa4 = { 7b cc [2] 0f d4 [2] 48 d6 [2] 0f c7 [2] 41 cb [2] 4d c1 [2] 5a ca [2] 41 84 [2] 7c }

  condition:
    any of them
}