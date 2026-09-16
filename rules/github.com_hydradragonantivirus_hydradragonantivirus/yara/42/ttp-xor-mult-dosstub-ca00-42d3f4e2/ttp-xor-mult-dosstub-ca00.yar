rule TTP_XOR_MULT_DOSStub_ca00 {
  strings:
    $key_ca00 = { 9e 68 [2] ea 70 [2] ad 72 [2] ea 63 [2] a4 6f [2] a8 65 [2] bf 6e [2] a4 20 [2] 99 }

  condition:
    any of them
}