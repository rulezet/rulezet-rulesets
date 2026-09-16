rule TTP_XOR_MULT_DOSStub_c415 {
  strings:
    $key_c415 = { 90 7d [2] e4 65 [2] a3 67 [2] e4 76 [2] aa 7a [2] a6 70 [2] b1 7b [2] aa 35 [2] 97 }

  condition:
    any of them
}