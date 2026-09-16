rule TTP_XOR_MULT_DOSStub_c448 {
  strings:
    $key_c448 = { 90 20 [2] e4 38 [2] a3 3a [2] e4 2b [2] aa 27 [2] a6 2d [2] b1 26 [2] aa 68 [2] 97 }

  condition:
    any of them
}