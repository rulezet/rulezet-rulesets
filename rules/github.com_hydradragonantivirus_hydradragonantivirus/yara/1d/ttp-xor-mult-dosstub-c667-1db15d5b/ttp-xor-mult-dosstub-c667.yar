rule TTP_XOR_MULT_DOSStub_c667 {
  strings:
    $key_c667 = { 92 0f [2] e6 17 [2] a1 15 [2] e6 04 [2] a8 08 [2] a4 02 [2] b3 09 [2] a8 47 [2] 95 }

  condition:
    any of them
}