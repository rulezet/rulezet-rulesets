rule TTP_XOR_MULT_DOSStub_c75c {
  strings:
    $key_c75c = { 93 34 [2] e7 2c [2] a0 2e [2] e7 3f [2] a9 33 [2] a5 39 [2] b2 32 [2] a9 7c [2] 94 }

  condition:
    any of them
}