rule TTP_XOR_MULT_DOSStub_c671 {
  strings:
    $key_c671 = { 92 19 [2] e6 01 [2] a1 03 [2] e6 12 [2] a8 1e [2] a4 14 [2] b3 1f [2] a8 51 [2] 95 }

  condition:
    any of them
}