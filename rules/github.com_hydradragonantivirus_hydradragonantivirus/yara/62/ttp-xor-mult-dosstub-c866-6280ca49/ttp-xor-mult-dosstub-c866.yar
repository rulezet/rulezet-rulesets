rule TTP_XOR_MULT_DOSStub_c866 {
  strings:
    $key_c866 = { 9c 0e [2] e8 16 [2] af 14 [2] e8 05 [2] a6 09 [2] aa 03 [2] bd 08 [2] a6 46 [2] 9b }

  condition:
    any of them
}