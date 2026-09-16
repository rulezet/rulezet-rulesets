rule TTP_XOR_MULT_DOSStub_ca30 {
  strings:
    $key_ca30 = { 9e 58 [2] ea 40 [2] ad 42 [2] ea 53 [2] a4 5f [2] a8 55 [2] bf 5e [2] a4 10 [2] 99 }

  condition:
    any of them
}