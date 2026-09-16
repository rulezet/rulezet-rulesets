rule TTP_XOR_MULT_DOSStub_c738 {
  strings:
    $key_c738 = { 93 50 [2] e7 48 [2] a0 4a [2] e7 5b [2] a9 57 [2] a5 5d [2] b2 56 [2] a9 18 [2] 94 }

  condition:
    any of them
}