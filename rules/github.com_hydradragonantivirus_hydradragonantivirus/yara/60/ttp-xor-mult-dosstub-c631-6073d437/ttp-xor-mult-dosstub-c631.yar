rule TTP_XOR_MULT_DOSStub_c631 {
  strings:
    $key_c631 = { 92 59 [2] e6 41 [2] a1 43 [2] e6 52 [2] a8 5e [2] a4 54 [2] b3 5f [2] a8 11 [2] 95 }

  condition:
    any of them
}