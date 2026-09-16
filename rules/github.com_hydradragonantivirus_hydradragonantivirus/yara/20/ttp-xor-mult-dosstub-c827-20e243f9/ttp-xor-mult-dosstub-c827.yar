rule TTP_XOR_MULT_DOSStub_c827 {
  strings:
    $key_c827 = { 9c 4f [2] e8 57 [2] af 55 [2] e8 44 [2] a6 48 [2] aa 42 [2] bd 49 [2] a6 07 [2] 9b }

  condition:
    any of them
}