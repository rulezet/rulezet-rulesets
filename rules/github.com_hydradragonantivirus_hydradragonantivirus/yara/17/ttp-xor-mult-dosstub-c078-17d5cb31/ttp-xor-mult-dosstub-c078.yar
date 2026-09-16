rule TTP_XOR_MULT_DOSStub_c078 {
  strings:
    $key_c078 = { 94 10 [2] e0 08 [2] a7 0a [2] e0 1b [2] ae 17 [2] a2 1d [2] b5 16 [2] ae 58 [2] 93 }

  condition:
    any of them
}