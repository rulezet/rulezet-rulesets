rule TTP_XOR_MULT_DOSStub_c649 {
  strings:
    $key_c649 = { 92 21 [2] e6 39 [2] a1 3b [2] e6 2a [2] a8 26 [2] a4 2c [2] b3 27 [2] a8 69 [2] 95 }

  condition:
    any of them
}