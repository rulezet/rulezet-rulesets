rule TTP_XOR_MULT_DOSStub_ca4a {
  strings:
    $key_ca4a = { 9e 22 [2] ea 3a [2] ad 38 [2] ea 29 [2] a4 25 [2] a8 2f [2] bf 24 [2] a4 6a [2] 99 }

  condition:
    any of them
}