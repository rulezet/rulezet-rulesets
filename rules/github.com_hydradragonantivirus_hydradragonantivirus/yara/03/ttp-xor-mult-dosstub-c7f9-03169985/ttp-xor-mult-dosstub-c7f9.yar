rule TTP_XOR_MULT_DOSStub_c7f9 {
  strings:
    $key_c7f9 = { 93 91 [2] e7 89 [2] a0 8b [2] e7 9a [2] a9 96 [2] a5 9c [2] b2 97 [2] a9 d9 [2] 94 }

  condition:
    any of them
}