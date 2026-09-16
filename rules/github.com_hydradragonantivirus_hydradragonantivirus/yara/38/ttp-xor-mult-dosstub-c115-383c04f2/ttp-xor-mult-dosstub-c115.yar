rule TTP_XOR_MULT_DOSStub_c115 {
  strings:
    $key_c115 = { 95 7d [2] e1 65 [2] a6 67 [2] e1 76 [2] af 7a [2] a3 70 [2] b4 7b [2] af 35 [2] 92 }

  condition:
    any of them
}