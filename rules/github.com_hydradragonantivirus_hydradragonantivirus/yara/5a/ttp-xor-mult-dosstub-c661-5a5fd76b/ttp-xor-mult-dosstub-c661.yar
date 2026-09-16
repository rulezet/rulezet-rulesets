rule TTP_XOR_MULT_DOSStub_c661 {
  strings:
    $key_c661 = { 92 09 [2] e6 11 [2] a1 13 [2] e6 02 [2] a8 0e [2] a4 04 [2] b3 0f [2] a8 41 [2] 95 }

  condition:
    any of them
}