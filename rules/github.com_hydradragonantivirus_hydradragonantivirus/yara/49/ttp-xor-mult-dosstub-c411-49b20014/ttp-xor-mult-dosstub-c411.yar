rule TTP_XOR_MULT_DOSStub_c411 {
  strings:
    $key_c411 = { 90 79 [2] e4 61 [2] a3 63 [2] e4 72 [2] aa 7e [2] a6 74 [2] b1 7f [2] aa 31 [2] 97 }

  condition:
    any of them
}