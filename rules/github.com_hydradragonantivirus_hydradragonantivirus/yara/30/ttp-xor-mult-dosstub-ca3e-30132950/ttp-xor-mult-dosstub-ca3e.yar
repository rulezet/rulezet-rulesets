rule TTP_XOR_MULT_DOSStub_ca3e {
  strings:
    $key_ca3e = { 9e 56 [2] ea 4e [2] ad 4c [2] ea 5d [2] a4 51 [2] a8 5b [2] bf 50 [2] a4 1e [2] 99 }

  condition:
    any of them
}