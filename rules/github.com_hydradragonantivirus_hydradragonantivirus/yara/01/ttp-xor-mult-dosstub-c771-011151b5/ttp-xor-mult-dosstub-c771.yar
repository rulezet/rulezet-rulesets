rule TTP_XOR_MULT_DOSStub_c771 {
  strings:
    $key_c771 = { 93 19 [2] e7 01 [2] a0 03 [2] e7 12 [2] a9 1e [2] a5 14 [2] b2 1f [2] a9 51 [2] 94 }

  condition:
    any of them
}