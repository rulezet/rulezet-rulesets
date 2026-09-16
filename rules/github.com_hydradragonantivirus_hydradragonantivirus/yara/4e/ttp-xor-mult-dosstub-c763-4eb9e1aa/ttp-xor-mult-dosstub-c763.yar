rule TTP_XOR_MULT_DOSStub_c763 {
  strings:
    $key_c763 = { 93 0b [2] e7 13 [2] a0 11 [2] e7 00 [2] a9 0c [2] a5 06 [2] b2 0d [2] a9 43 [2] 94 }

  condition:
    any of them
}