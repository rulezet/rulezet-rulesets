rule TTP_XOR_MULT_DOSStub_c012 {
  strings:
    $key_c012 = { 94 7a [2] e0 62 [2] a7 60 [2] e0 71 [2] ae 7d [2] a2 77 [2] b5 7c [2] ae 32 [2] 93 }

  condition:
    any of them
}