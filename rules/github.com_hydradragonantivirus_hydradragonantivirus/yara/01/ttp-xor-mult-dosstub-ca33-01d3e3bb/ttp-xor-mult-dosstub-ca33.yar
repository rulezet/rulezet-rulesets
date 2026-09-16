rule TTP_XOR_MULT_DOSStub_ca33 {
  strings:
    $key_ca33 = { 9e 5b [2] ea 43 [2] ad 41 [2] ea 50 [2] a4 5c [2] a8 56 [2] bf 5d [2] a4 13 [2] 99 }

  condition:
    any of them
}