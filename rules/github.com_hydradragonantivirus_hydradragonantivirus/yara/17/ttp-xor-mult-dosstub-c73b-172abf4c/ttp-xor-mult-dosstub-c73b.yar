rule TTP_XOR_MULT_DOSStub_c73b {
  strings:
    $key_c73b = { 93 53 [2] e7 4b [2] a0 49 [2] e7 58 [2] a9 54 [2] a5 5e [2] b2 55 [2] a9 1b [2] 94 }

  condition:
    any of them
}