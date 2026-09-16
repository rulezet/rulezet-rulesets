rule TTP_XOR_MULT_DOSStub_c015 {
  strings:
    $key_c015 = { 94 7d [2] e0 65 [2] a7 67 [2] e0 76 [2] ae 7a [2] a2 70 [2] b5 7b [2] ae 35 [2] 93 }

  condition:
    any of them
}