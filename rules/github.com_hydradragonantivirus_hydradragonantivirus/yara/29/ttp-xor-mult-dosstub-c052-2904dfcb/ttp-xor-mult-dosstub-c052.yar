rule TTP_XOR_MULT_DOSStub_c052 {
  strings:
    $key_c052 = { 94 3a [2] e0 22 [2] a7 20 [2] e0 31 [2] ae 3d [2] a2 37 [2] b5 3c [2] ae 72 [2] 93 }

  condition:
    any of them
}