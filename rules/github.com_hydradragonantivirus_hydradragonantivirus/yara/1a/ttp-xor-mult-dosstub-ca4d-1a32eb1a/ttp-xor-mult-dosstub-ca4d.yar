rule TTP_XOR_MULT_DOSStub_ca4d {
  strings:
    $key_ca4d = { 9e 25 [2] ea 3d [2] ad 3f [2] ea 2e [2] a4 22 [2] a8 28 [2] bf 23 [2] a4 6d [2] 99 }

  condition:
    any of them
}