rule TTP_XOR_MULT_DOSStub_c114 {
  strings:
    $key_c114 = { 95 7c [2] e1 64 [2] a6 66 [2] e1 77 [2] af 7b [2] a3 71 [2] b4 7a [2] af 34 [2] 92 }

  condition:
    any of them
}