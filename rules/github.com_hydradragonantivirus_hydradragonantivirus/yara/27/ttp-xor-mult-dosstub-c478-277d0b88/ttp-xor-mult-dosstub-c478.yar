rule TTP_XOR_MULT_DOSStub_c478 {
  strings:
    $key_c478 = { 90 10 [2] e4 08 [2] a3 0a [2] e4 1b [2] aa 17 [2] a6 1d [2] b1 16 [2] aa 58 [2] 97 }

  condition:
    any of them
}