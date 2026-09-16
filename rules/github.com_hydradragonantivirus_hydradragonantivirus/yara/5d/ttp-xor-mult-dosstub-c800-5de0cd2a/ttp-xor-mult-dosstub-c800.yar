rule TTP_XOR_MULT_DOSStub_c800 {
  strings:
    $key_c800 = { 9c 68 [2] e8 70 [2] af 72 [2] e8 63 [2] a6 6f [2] aa 65 [2] bd 6e [2] a6 20 [2] 9b }

  condition:
    any of them
}