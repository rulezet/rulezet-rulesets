rule TTP_XOR_MULT_DOSStub_c764 {
  strings:
    $key_c764 = { 93 0c [2] e7 14 [2] a0 16 [2] e7 07 [2] a9 0b [2] a5 01 [2] b2 0a [2] a9 44 [2] 94 }

  condition:
    any of them
}