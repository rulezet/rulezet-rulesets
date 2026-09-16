rule TTP_XOR_MULT_DOSStub_ca75 {
  strings:
    $key_ca75 = { 9e 1d [2] ea 05 [2] ad 07 [2] ea 16 [2] a4 1a [2] a8 10 [2] bf 1b [2] a4 55 [2] 99 }

  condition:
    any of them
}