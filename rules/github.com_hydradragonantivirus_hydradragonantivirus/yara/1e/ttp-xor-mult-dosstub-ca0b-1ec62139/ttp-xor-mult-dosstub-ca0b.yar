rule TTP_XOR_MULT_DOSStub_ca0b {
  strings:
    $key_ca0b = { 9e 63 [2] ea 7b [2] ad 79 [2] ea 68 [2] a4 64 [2] a8 6e [2] bf 65 [2] a4 2b [2] 99 }

  condition:
    any of them
}