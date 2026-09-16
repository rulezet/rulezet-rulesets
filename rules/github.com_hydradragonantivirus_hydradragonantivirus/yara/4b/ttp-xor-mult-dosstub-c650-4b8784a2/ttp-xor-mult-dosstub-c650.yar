rule TTP_XOR_MULT_DOSStub_c650 {
  strings:
    $key_c650 = { 92 38 [2] e6 20 [2] a1 22 [2] e6 33 [2] a8 3f [2] a4 35 [2] b3 3e [2] a8 70 [2] 95 }

  condition:
    any of them
}