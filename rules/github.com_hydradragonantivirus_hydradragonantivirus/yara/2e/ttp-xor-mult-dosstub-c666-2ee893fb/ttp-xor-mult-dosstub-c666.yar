rule TTP_XOR_MULT_DOSStub_c666 {
  strings:
    $key_c666 = { 92 0e [2] e6 16 [2] a1 14 [2] e6 05 [2] a8 09 [2] a4 03 [2] b3 08 [2] a8 46 [2] 95 }

  condition:
    any of them
}