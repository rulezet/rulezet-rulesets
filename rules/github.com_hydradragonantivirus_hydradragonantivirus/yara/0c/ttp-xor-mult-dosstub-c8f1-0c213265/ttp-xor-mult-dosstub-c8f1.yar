rule TTP_XOR_MULT_DOSStub_c8f1 {
  strings:
    $key_c8f1 = { 9c 99 [2] e8 81 [2] af 83 [2] e8 92 [2] a6 9e [2] aa 94 [2] bd 9f [2] a6 d1 [2] 9b }

  condition:
    any of them
}