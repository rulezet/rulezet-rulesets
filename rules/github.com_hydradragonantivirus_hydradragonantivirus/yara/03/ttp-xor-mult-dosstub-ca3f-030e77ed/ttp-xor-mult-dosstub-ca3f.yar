rule TTP_XOR_MULT_DOSStub_ca3f {
  strings:
    $key_ca3f = { 9e 57 [2] ea 4f [2] ad 4d [2] ea 5c [2] a4 50 [2] a8 5a [2] bf 51 [2] a4 1f [2] 99 }

  condition:
    any of them
}