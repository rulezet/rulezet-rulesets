rule TTP_XOR_MULT_DOSStub_da8b {
  strings:
    $key_da8b = { 8e e3 [2] fa fb [2] bd f9 [2] fa e8 [2] b4 e4 [2] b8 ee [2] af e5 [2] b4 ab [2] 89 }

  condition:
    any of them
}