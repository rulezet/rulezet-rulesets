rule TTP_XOR_MULT_DOSStub_c702 {
  strings:
    $key_c702 = { 93 6a [2] e7 72 [2] a0 70 [2] e7 61 [2] a9 6d [2] a5 67 [2] b2 6c [2] a9 22 [2] 94 }

  condition:
    any of them
}