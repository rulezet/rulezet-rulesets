rule TTP_XOR_MULT_DOSStub_c479 {
  strings:
    $key_c479 = { 90 11 [2] e4 09 [2] a3 0b [2] e4 1a [2] aa 16 [2] a6 1c [2] b1 17 [2] aa 59 [2] 97 }

  condition:
    any of them
}