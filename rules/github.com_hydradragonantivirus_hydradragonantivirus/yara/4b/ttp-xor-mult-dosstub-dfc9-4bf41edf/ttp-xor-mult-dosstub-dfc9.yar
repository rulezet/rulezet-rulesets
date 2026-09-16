rule TTP_XOR_MULT_DOSStub_dfc9 {
  strings:
    $key_dfc9 = { 8b a1 [2] ff b9 [2] b8 bb [2] ff aa [2] b1 a6 [2] bd ac [2] aa a7 [2] b1 e9 [2] 8c }

  condition:
    any of them
}