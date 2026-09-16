rule TTP_XOR_MULT_DOSStub_ca7f {
  strings:
    $key_ca7f = { 9e 17 [2] ea 0f [2] ad 0d [2] ea 1c [2] a4 10 [2] a8 1a [2] bf 11 [2] a4 5f [2] 99 }

  condition:
    any of them
}