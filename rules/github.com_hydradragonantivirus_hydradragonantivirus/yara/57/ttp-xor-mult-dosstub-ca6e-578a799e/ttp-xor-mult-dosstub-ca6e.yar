rule TTP_XOR_MULT_DOSStub_ca6e {
  strings:
    $key_ca6e = { 9e 06 [2] ea 1e [2] ad 1c [2] ea 0d [2] a4 01 [2] a8 0b [2] bf 00 [2] a4 4e [2] 99 }

  condition:
    any of them
}