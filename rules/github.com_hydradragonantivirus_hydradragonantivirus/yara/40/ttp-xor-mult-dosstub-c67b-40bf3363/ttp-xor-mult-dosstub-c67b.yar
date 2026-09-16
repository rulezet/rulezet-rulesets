rule TTP_XOR_MULT_DOSStub_c67b {
  strings:
    $key_c67b = { 92 13 [2] e6 0b [2] a1 09 [2] e6 18 [2] a8 14 [2] a4 1e [2] b3 15 [2] a8 5b [2] 95 }

  condition:
    any of them
}