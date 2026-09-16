rule TTP_XOR_MULT_DOSStub_c059 {
  strings:
    $key_c059 = { 94 31 [2] e0 29 [2] a7 2b [2] e0 3a [2] ae 36 [2] a2 3c [2] b5 37 [2] ae 79 [2] 93 }

  condition:
    any of them
}