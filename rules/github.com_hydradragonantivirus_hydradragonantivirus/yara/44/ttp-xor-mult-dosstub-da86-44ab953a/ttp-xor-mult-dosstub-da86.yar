rule TTP_XOR_MULT_DOSStub_da86 {
  strings:
    $key_da86 = { 8e ee [2] fa f6 [2] bd f4 [2] fa e5 [2] b4 e9 [2] b8 e3 [2] af e8 [2] b4 a6 [2] 89 }

  condition:
    any of them
}