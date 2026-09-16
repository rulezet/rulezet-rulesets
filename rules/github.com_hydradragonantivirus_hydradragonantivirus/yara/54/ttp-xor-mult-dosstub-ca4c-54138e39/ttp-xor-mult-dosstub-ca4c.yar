rule TTP_XOR_MULT_DOSStub_ca4c {
  strings:
    $key_ca4c = { 9e 24 [2] ea 3c [2] ad 3e [2] ea 2f [2] a4 23 [2] a8 29 [2] bf 22 [2] a4 6c [2] 99 }

  condition:
    any of them
}