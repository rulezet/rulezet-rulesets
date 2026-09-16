rule TTP_XOR_MULT_DOSStub_c147 {
  strings:
    $key_c147 = { 95 2f [2] e1 37 [2] a6 35 [2] e1 24 [2] af 28 [2] a3 22 [2] b4 29 [2] af 67 [2] 92 }

  condition:
    any of them
}