rule TTP_XOR_MULT_DOSStub_c138 {
  strings:
    $key_c138 = { 95 50 [2] e1 48 [2] a6 4a [2] e1 5b [2] af 57 [2] a3 5d [2] b4 56 [2] af 18 [2] 92 }

  condition:
    any of them
}