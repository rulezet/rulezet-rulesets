rule TTP_XOR_MULT_DOSStub_c456 {
  strings:
    $key_c456 = { 90 3e [2] e4 26 [2] a3 24 [2] e4 35 [2] aa 39 [2] a6 33 [2] b1 38 [2] aa 76 [2] 97 }

  condition:
    any of them
}