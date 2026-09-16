rule TTP_XOR_MULT_DOSStub_c7f2 {
  strings:
    $key_c7f2 = { 93 9a [2] e7 82 [2] a0 80 [2] e7 91 [2] a9 9d [2] a5 97 [2] b2 9c [2] a9 d2 [2] 94 }

  condition:
    any of them
}