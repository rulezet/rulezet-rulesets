rule TTP_XOR_MULT_DOSStub_c166 {
  strings:
    $key_c166 = { 95 0e [2] e1 16 [2] a6 14 [2] e1 05 [2] af 09 [2] a3 03 [2] b4 08 [2] af 46 [2] 92 }

  condition:
    any of them
}