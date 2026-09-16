rule TTP_XOR_MULT_DOSStub_38a4 {
  strings:
    $key_38a4 = { 6c cc [2] 18 d4 [2] 5f d6 [2] 18 c7 [2] 56 cb [2] 5a c1 [2] 4d ca [2] 56 84 [2] 6b }

  condition:
    any of them
}