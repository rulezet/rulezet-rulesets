rule TTP_XOR_MULT_DOSStub_c457 {
  strings:
    $key_c457 = { 90 3f [2] e4 27 [2] a3 25 [2] e4 34 [2] aa 38 [2] a6 32 [2] b1 39 [2] aa 77 [2] 97 }

  condition:
    any of them
}