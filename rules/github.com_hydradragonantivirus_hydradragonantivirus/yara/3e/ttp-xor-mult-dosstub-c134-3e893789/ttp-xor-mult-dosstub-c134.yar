rule TTP_XOR_MULT_DOSStub_c134 {
  strings:
    $key_c134 = { 95 5c [2] e1 44 [2] a6 46 [2] e1 57 [2] af 5b [2] a3 51 [2] b4 5a [2] af 14 [2] 92 }

  condition:
    any of them
}