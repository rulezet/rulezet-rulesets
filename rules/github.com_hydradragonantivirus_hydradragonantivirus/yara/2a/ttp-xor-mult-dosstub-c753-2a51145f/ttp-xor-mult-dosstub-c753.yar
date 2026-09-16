rule TTP_XOR_MULT_DOSStub_c753 {
  strings:
    $key_c753 = { 93 3b [2] e7 23 [2] a0 21 [2] e7 30 [2] a9 3c [2] a5 36 [2] b2 3d [2] a9 73 [2] 94 }

  condition:
    any of them
}