rule TTP_XOR_MULT_DOSStub_ca1d {
  strings:
    $key_ca1d = { 9e 75 [2] ea 6d [2] ad 6f [2] ea 7e [2] a4 72 [2] a8 78 [2] bf 73 [2] a4 3d [2] 99 }

  condition:
    any of them
}