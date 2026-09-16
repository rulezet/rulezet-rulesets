rule TTP_XOR_MULT_DOSStub_c003 {
  strings:
    $key_c003 = { 94 6b [2] e0 73 [2] a7 71 [2] e0 60 [2] ae 6c [2] a2 66 [2] b5 6d [2] ae 23 [2] 93 }

  condition:
    any of them
}