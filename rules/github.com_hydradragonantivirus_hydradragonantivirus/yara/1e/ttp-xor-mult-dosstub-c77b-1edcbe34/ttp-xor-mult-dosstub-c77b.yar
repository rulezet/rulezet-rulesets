rule TTP_XOR_MULT_DOSStub_c77b {
  strings:
    $key_c77b = { 93 13 [2] e7 0b [2] a0 09 [2] e7 18 [2] a9 14 [2] a5 1e [2] b2 15 [2] a9 5b [2] 94 }

  condition:
    any of them
}