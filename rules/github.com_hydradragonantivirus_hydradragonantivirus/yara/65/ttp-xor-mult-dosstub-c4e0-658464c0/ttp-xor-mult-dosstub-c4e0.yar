rule TTP_XOR_MULT_DOSStub_c4e0 {
  strings:
    $key_c4e0 = { 90 88 [2] e4 90 [2] a3 92 [2] e4 83 [2] aa 8f [2] a6 85 [2] b1 8e [2] aa c0 [2] 97 }

  condition:
    any of them
}