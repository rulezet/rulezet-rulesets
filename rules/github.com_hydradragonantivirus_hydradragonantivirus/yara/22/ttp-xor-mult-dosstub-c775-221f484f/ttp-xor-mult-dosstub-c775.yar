rule TTP_XOR_MULT_DOSStub_c775 {
  strings:
    $key_c775 = { 93 1d [2] e7 05 [2] a0 07 [2] e7 16 [2] a9 1a [2] a5 10 [2] b2 1b [2] a9 55 [2] 94 }

  condition:
    any of them
}