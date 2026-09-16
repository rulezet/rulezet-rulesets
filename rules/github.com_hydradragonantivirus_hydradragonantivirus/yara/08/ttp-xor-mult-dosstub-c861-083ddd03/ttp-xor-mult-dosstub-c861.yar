rule TTP_XOR_MULT_DOSStub_c861 {
  strings:
    $key_c861 = { 9c 09 [2] e8 11 [2] af 13 [2] e8 02 [2] a6 0e [2] aa 04 [2] bd 0f [2] a6 41 [2] 9b }

  condition:
    any of them
}