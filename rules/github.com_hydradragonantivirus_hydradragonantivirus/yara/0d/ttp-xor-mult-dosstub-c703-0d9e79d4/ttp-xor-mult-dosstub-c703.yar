rule TTP_XOR_MULT_DOSStub_c703 {
  strings:
    $key_c703 = { 93 6b [2] e7 73 [2] a0 71 [2] e7 60 [2] a9 6c [2] a5 66 [2] b2 6d [2] a9 23 [2] 94 }

  condition:
    any of them
}