rule TTP_XOR_MULT_DOSStub_c472 {
  strings:
    $key_c472 = { 90 1a [2] e4 02 [2] a3 00 [2] e4 11 [2] aa 1d [2] a6 17 [2] b1 1c [2] aa 52 [2] 97 }

  condition:
    any of them
}