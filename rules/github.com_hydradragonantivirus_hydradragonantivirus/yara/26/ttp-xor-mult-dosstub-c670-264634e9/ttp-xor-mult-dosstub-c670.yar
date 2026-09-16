rule TTP_XOR_MULT_DOSStub_c670 {
  strings:
    $key_c670 = { 92 18 [2] e6 00 [2] a1 02 [2] e6 13 [2] a8 1f [2] a4 15 [2] b3 1e [2] a8 50 [2] 95 }

  condition:
    any of them
}