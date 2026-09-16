rule TTP_XOR_MULT_DOSStub_c65b {
  strings:
    $key_c65b = { 92 33 [2] e6 2b [2] a1 29 [2] e6 38 [2] a8 34 [2] a4 3e [2] b3 35 [2] a8 7b [2] 95 }

  condition:
    any of them
}