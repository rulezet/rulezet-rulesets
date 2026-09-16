rule TTP_XOR_MULT_DOSStub_c405 {
  strings:
    $key_c405 = { 90 6d [2] e4 75 [2] a3 77 [2] e4 66 [2] aa 6a [2] a6 60 [2] b1 6b [2] aa 25 [2] 97 }

  condition:
    any of them
}