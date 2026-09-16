rule TTP_XOR_MULT_DOSStub_c811 {
  strings:
    $key_c811 = { 9c 79 [2] e8 61 [2] af 63 [2] e8 72 [2] a6 7e [2] aa 74 [2] bd 7f [2] a6 31 [2] 9b }

  condition:
    any of them
}