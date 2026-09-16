rule TTP_XOR_MULT_DOSStub_ca5e {
  strings:
    $key_ca5e = { 9e 36 [2] ea 2e [2] ad 2c [2] ea 3d [2] a4 31 [2] a8 3b [2] bf 30 [2] a4 7e [2] 99 }

  condition:
    any of them
}