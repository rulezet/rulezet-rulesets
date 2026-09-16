rule TTP_XOR_MULT_DOSStub_ca35 {
  strings:
    $key_ca35 = { 9e 5d [2] ea 45 [2] ad 47 [2] ea 56 [2] a4 5a [2] a8 50 [2] bf 5b [2] a4 15 [2] 99 }

  condition:
    any of them
}