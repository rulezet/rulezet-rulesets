rule TTP_XOR_MULT_DOSStub_c636 {
  strings:
    $key_c636 = { 92 5e [2] e6 46 [2] a1 44 [2] e6 55 [2] a8 59 [2] a4 53 [2] b3 58 [2] a8 16 [2] 95 }

  condition:
    any of them
}