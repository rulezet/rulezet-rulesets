rule TTP_XOR_MULT_DOSStub_ebde {
  strings:
    $key_ebde = { bf b6 [2] cb ae [2] 8c ac [2] cb bd [2] 85 b1 [2] 89 bb [2] 9e b0 [2] 85 fe [2] b8 }

  condition:
    any of them
}