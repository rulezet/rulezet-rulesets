rule TTP_XOR_MULT_DOSStub_ca2f {
  strings:
    $key_ca2f = { 9e 47 [2] ea 5f [2] ad 5d [2] ea 4c [2] a4 40 [2] a8 4a [2] bf 41 [2] a4 0f [2] 99 }

  condition:
    any of them
}