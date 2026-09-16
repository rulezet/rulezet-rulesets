rule TTP_XOR_MULT_DOSStub_c008 {
  strings:
    $key_c008 = { 94 60 [2] e0 78 [2] a7 7a [2] e0 6b [2] ae 67 [2] a2 6d [2] b5 66 [2] ae 28 [2] 93 }

  condition:
    any of them
}