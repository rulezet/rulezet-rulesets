rule TTP_XOR_MULT_DOSStub_ca53 {
  strings:
    $key_ca53 = { 9e 3b [2] ea 23 [2] ad 21 [2] ea 30 [2] a4 3c [2] a8 36 [2] bf 3d [2] a4 73 [2] 99 }

  condition:
    any of them
}