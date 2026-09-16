rule TTP_XOR_MULT_DOSStub_c467 {
  strings:
    $key_c467 = { 90 0f [2] e4 17 [2] a3 15 [2] e4 04 [2] aa 08 [2] a6 02 [2] b1 09 [2] aa 47 [2] 97 }

  condition:
    any of them
}