rule TTP_XOR_MULT_DOSStub_ca6f {
  strings:
    $key_ca6f = { 9e 07 [2] ea 1f [2] ad 1d [2] ea 0c [2] a4 00 [2] a8 0a [2] bf 01 [2] a4 4f [2] 99 }

  condition:
    any of them
}