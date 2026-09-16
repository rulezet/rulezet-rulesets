rule TTP_XOR_MULT_DOSStub_c8a2 {
  strings:
    $key_c8a2 = { 9c ca [2] e8 d2 [2] af d0 [2] e8 c1 [2] a6 cd [2] aa c7 [2] bd cc [2] a6 82 [2] 9b }

  condition:
    any of them
}