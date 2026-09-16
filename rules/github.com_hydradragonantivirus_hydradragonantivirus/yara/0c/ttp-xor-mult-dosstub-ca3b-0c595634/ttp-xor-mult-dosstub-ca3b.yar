rule TTP_XOR_MULT_DOSStub_ca3b {
  strings:
    $key_ca3b = { 9e 53 [2] ea 4b [2] ad 49 [2] ea 58 [2] a4 54 [2] a8 5e [2] bf 55 [2] a4 1b [2] 99 }

  condition:
    any of them
}