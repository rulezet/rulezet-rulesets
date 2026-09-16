rule TTP_XOR_MULT_DOSStub_c461 {
  strings:
    $key_c461 = { 90 09 [2] e4 11 [2] a3 13 [2] e4 02 [2] aa 0e [2] a6 04 [2] b1 0f [2] aa 41 [2] 97 }

  condition:
    any of them
}