rule TTP_XOR_MULT_DOSStub_ca2b {
  strings:
    $key_ca2b = { 9e 43 [2] ea 5b [2] ad 59 [2] ea 48 [2] a4 44 [2] a8 4e [2] bf 45 [2] a4 0b [2] 99 }

  condition:
    any of them
}