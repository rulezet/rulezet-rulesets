rule TTP_XOR_MULT_DOSStub_c1f8 {
  strings:
    $key_c1f8 = { 95 90 [2] e1 88 [2] a6 8a [2] e1 9b [2] af 97 [2] a3 9d [2] b4 96 [2] af d8 [2] 92 }

  condition:
    any of them
}