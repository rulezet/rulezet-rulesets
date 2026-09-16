rule TTP_XOR_MULT_DOSStub_c64b {
  strings:
    $key_c64b = { 92 23 [2] e6 3b [2] a1 39 [2] e6 28 [2] a8 24 [2] a4 2e [2] b3 25 [2] a8 6b [2] 95 }

  condition:
    any of them
}