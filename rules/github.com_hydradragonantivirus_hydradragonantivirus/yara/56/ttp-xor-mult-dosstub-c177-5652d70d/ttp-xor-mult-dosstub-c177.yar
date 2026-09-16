rule TTP_XOR_MULT_DOSStub_c177 {
  strings:
    $key_c177 = { 95 1f [2] e1 07 [2] a6 05 [2] e1 14 [2] af 18 [2] a3 12 [2] b4 19 [2] af 57 [2] 92 }

  condition:
    any of them
}