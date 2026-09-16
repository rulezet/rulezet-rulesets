rule TTP_XOR_MULT_DOSStub_c713 {
  strings:
    $key_c713 = { 93 7b [2] e7 63 [2] a0 61 [2] e7 70 [2] a9 7c [2] a5 76 [2] b2 7d [2] a9 33 [2] 94 }

  condition:
    any of them
}