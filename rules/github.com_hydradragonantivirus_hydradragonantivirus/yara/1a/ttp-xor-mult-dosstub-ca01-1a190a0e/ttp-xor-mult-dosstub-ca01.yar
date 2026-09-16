rule TTP_XOR_MULT_DOSStub_ca01 {
  strings:
    $key_ca01 = { 9e 69 [2] ea 71 [2] ad 73 [2] ea 62 [2] a4 6e [2] a8 64 [2] bf 6f [2] a4 21 [2] 99 }

  condition:
    any of them
}