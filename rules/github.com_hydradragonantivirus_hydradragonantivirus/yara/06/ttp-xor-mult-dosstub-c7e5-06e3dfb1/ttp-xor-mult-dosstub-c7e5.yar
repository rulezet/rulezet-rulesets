rule TTP_XOR_MULT_DOSStub_c7e5 {
  strings:
    $key_c7e5 = { 93 8d [2] e7 95 [2] a0 97 [2] e7 86 [2] a9 8a [2] a5 80 [2] b2 8b [2] a9 c5 [2] 94 }

  condition:
    any of them
}