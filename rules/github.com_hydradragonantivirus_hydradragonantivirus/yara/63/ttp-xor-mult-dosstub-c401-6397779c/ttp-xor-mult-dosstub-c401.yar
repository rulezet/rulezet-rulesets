rule TTP_XOR_MULT_DOSStub_c401 {
  strings:
    $key_c401 = { 90 69 [2] e4 71 [2] a3 73 [2] e4 62 [2] aa 6e [2] a6 64 [2] b1 6f [2] aa 21 [2] 97 }

  condition:
    any of them
}