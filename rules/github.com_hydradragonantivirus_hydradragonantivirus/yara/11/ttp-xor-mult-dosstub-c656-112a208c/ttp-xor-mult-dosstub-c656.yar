rule TTP_XOR_MULT_DOSStub_c656 {
  strings:
    $key_c656 = { 92 3e [2] e6 26 [2] a1 24 [2] e6 35 [2] a8 39 [2] a4 33 [2] b3 38 [2] a8 76 [2] 95 }

  condition:
    any of them
}