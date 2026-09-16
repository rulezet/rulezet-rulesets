rule TTP_XOR_MULT_DOSStub_c769 {
  strings:
    $key_c769 = { 93 01 [2] e7 19 [2] a0 1b [2] e7 0a [2] a9 06 [2] a5 0c [2] b2 07 [2] a9 49 [2] 94 }

  condition:
    any of them
}