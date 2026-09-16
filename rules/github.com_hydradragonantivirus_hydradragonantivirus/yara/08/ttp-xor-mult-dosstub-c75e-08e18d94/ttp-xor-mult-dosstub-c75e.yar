rule TTP_XOR_MULT_DOSStub_c75e {
  strings:
    $key_c75e = { 93 36 [2] e7 2e [2] a0 2c [2] e7 3d [2] a9 31 [2] a5 3b [2] b2 30 [2] a9 7e [2] 94 }

  condition:
    any of them
}