rule TTP_XOR_MULT_DOSStub_c8f0 {
  strings:
    $key_c8f0 = { 9c 98 [2] e8 80 [2] af 82 [2] e8 93 [2] a6 9f [2] aa 95 [2] bd 9e [2] a6 d0 [2] 9b }

  condition:
    any of them
}