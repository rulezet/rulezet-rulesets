rule TTP_XOR_MULT_DOSStub_c676 {
  strings:
    $key_c676 = { 92 1e [2] e6 06 [2] a1 04 [2] e6 15 [2] a8 19 [2] a4 13 [2] b3 18 [2] a8 56 [2] 95 }

  condition:
    any of them
}