rule TTP_XOR_MULT_DOSStub_ca7e {
  strings:
    $key_ca7e = { 9e 16 [2] ea 0e [2] ad 0c [2] ea 1d [2] a4 11 [2] a8 1b [2] bf 10 [2] a4 5e [2] 99 }

  condition:
    any of them
}