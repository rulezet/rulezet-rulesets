rule TTP_XOR_MULT_DOSStub_c463 {
  strings:
    $key_c463 = { 90 0b [2] e4 13 [2] a3 11 [2] e4 00 [2] aa 0c [2] a6 06 [2] b1 0d [2] aa 43 [2] 97 }

  condition:
    any of them
}