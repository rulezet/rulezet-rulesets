rule TTP_XOR_MULT_DOSStub_ca1b {
  strings:
    $key_ca1b = { 9e 73 [2] ea 6b [2] ad 69 [2] ea 78 [2] a4 74 [2] a8 7e [2] bf 75 [2] a4 3b [2] 99 }

  condition:
    any of them
}