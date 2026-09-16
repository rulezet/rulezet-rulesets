rule TTP_XOR_MULT_DOSStub_c431 {
  strings:
    $key_c431 = { 90 59 [2] e4 41 [2] a3 43 [2] e4 52 [2] aa 5e [2] a6 54 [2] b1 5f [2] aa 11 [2] 97 }

  condition:
    any of them
}