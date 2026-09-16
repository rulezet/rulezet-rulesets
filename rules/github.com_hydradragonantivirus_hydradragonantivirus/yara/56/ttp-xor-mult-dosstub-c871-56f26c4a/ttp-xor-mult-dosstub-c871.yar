rule TTP_XOR_MULT_DOSStub_c871 {
  strings:
    $key_c871 = { 9c 19 [2] e8 01 [2] af 03 [2] e8 12 [2] a6 1e [2] aa 14 [2] bd 1f [2] a6 51 [2] 9b }

  condition:
    any of them
}