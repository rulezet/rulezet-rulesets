rule TTP_XOR_MULT_DOSStub_ca5d {
  strings:
    $key_ca5d = { 9e 35 [2] ea 2d [2] ad 2f [2] ea 3e [2] a4 32 [2] a8 38 [2] bf 33 [2] a4 7d [2] 99 }

  condition:
    any of them
}