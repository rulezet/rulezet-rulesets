rule TTP_XOR_MULT_DOSStub_c157 {
  strings:
    $key_c157 = { 95 3f [2] e1 27 [2] a6 25 [2] e1 34 [2] af 38 [2] a3 32 [2] b4 39 [2] af 77 [2] 92 }

  condition:
    any of them
}