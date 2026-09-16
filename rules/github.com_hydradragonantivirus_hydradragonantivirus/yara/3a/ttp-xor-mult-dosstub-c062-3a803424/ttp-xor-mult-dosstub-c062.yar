rule TTP_XOR_MULT_DOSStub_c062 {
  strings:
    $key_c062 = { 94 0a [2] e0 12 [2] a7 10 [2] e0 01 [2] ae 0d [2] a2 07 [2] b5 0c [2] ae 42 [2] 93 }

  condition:
    any of them
}