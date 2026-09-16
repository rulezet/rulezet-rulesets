rule TTP_XOR_MULT_DOSStub_ca13 {
  strings:
    $key_ca13 = { 9e 7b [2] ea 63 [2] ad 61 [2] ea 70 [2] a4 7c [2] a8 76 [2] bf 7d [2] a4 33 [2] 99 }

  condition:
    any of them
}