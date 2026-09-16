rule TTP_XOR_MULT_DOSStub_ca7d {
  strings:
    $key_ca7d = { 9e 15 [2] ea 0d [2] ad 0f [2] ea 1e [2] a4 12 [2] a8 18 [2] bf 13 [2] a4 5d [2] 99 }

  condition:
    any of them
}