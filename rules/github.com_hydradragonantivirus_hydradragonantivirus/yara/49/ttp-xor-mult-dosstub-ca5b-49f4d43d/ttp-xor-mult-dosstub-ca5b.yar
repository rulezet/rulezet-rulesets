rule TTP_XOR_MULT_DOSStub_ca5b {
  strings:
    $key_ca5b = { 9e 33 [2] ea 2b [2] ad 29 [2] ea 38 [2] a4 34 [2] a8 3e [2] bf 35 [2] a4 7b [2] 99 }

  condition:
    any of them
}