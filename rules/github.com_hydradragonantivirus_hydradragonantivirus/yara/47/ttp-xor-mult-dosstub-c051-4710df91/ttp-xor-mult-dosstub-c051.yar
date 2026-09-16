rule TTP_XOR_MULT_DOSStub_c051 {
  strings:
    $key_c051 = { 94 39 [2] e0 21 [2] a7 23 [2] e0 32 [2] ae 3e [2] a2 34 [2] b5 3f [2] ae 71 [2] 93 }

  condition:
    any of them
}