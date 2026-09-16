rule TTP_XOR_MULT_DOSStub_ca1e {
  strings:
    $key_ca1e = { 9e 76 [2] ea 6e [2] ad 6c [2] ea 7d [2] a4 71 [2] a8 7b [2] bf 70 [2] a4 3e [2] 99 }

  condition:
    any of them
}