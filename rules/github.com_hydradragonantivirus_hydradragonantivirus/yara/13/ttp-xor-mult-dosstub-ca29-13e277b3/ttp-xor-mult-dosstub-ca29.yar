rule TTP_XOR_MULT_DOSStub_ca29 {
  strings:
    $key_ca29 = { 9e 41 [2] ea 59 [2] ad 5b [2] ea 4a [2] a4 46 [2] a8 4c [2] bf 47 [2] a4 09 [2] 99 }

  condition:
    any of them
}