rule TTP_XOR_MULT_DOSStub_c856 {
  strings:
    $key_c856 = { 9c 3e [2] e8 26 [2] af 24 [2] e8 35 [2] a6 39 [2] aa 33 [2] bd 38 [2] a6 76 [2] 9b }

  condition:
    any of them
}