rule TTP_XOR_MULT_DOSStub_caf6 {
  strings:
    $key_caf6 = { 9e 9e [2] ea 86 [2] ad 84 [2] ea 95 [2] a4 99 [2] a8 93 [2] bf 98 [2] a4 d6 [2] 99 }

  condition:
    any of them
}