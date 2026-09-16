rule TTP_XOR_MULT_DOSStub_c446 {
  strings:
    $key_c446 = { 90 2e [2] e4 36 [2] a3 34 [2] e4 25 [2] aa 29 [2] a6 23 [2] b1 28 [2] aa 66 [2] 97 }

  condition:
    any of them
}