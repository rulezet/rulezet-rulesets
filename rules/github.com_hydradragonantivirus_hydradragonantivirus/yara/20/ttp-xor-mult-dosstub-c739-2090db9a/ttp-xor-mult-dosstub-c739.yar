rule TTP_XOR_MULT_DOSStub_c739 {
  strings:
    $key_c739 = { 93 51 [2] e7 49 [2] a0 4b [2] e7 5a [2] a9 56 [2] a5 5c [2] b2 57 [2] a9 19 [2] 94 }

  condition:
    any of them
}