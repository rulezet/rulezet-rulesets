rule TTP_XOR_MULT_DOSStub_c836 {
  strings:
    $key_c836 = { 9c 5e [2] e8 46 [2] af 44 [2] e8 55 [2] a6 59 [2] aa 53 [2] bd 58 [2] a6 16 [2] 9b }

  condition:
    any of them
}