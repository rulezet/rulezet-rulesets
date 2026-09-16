rule TTP_XOR_MULT_DOSStub_ca7c {
  strings:
    $key_ca7c = { 9e 14 [2] ea 0c [2] ad 0e [2] ea 1f [2] a4 13 [2] a8 19 [2] bf 12 [2] a4 5c [2] 99 }

  condition:
    any of them
}