rule TTP_XOR_MULT_DOSStub_c872 {
  strings:
    $key_c872 = { 9c 1a [2] e8 02 [2] af 00 [2] e8 11 [2] a6 1d [2] aa 17 [2] bd 1c [2] a6 52 [2] 9b }

  condition:
    any of them
}