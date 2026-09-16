rule TTP_XOR_MULT_DOSStub_c4e5 {
  strings:
    $key_c4e5 = { 90 8d [2] e4 95 [2] a3 97 [2] e4 86 [2] aa 8a [2] a6 80 [2] b1 8b [2] aa c5 [2] 97 }

  condition:
    any of them
}