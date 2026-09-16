rule TTP_XOR_MULT_DOSStub_ca71 {
  strings:
    $key_ca71 = { 9e 19 [2] ea 01 [2] ad 03 [2] ea 12 [2] a4 1e [2] a8 14 [2] bf 1f [2] a4 51 [2] 99 }

  condition:
    any of them
}