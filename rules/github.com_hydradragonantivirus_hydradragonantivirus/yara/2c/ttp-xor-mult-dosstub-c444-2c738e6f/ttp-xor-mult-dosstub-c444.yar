rule TTP_XOR_MULT_DOSStub_c444 {
  strings:
    $key_c444 = { 90 2c [2] e4 34 [2] a3 36 [2] e4 27 [2] aa 2b [2] a6 21 [2] b1 2a [2] aa 64 [2] 97 }

  condition:
    any of them
}