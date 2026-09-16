rule TTP_XOR_MULT_DOSStub_c4f1 {
  strings:
    $key_c4f1 = { 90 99 [2] e4 81 [2] a3 83 [2] e4 92 [2] aa 9e [2] a6 94 [2] b1 9f [2] aa d1 [2] 97 }

  condition:
    any of them
}