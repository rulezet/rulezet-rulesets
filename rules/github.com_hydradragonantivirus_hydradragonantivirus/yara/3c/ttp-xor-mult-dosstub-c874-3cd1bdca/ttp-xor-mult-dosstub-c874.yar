rule TTP_XOR_MULT_DOSStub_c874 {
  strings:
    $key_c874 = { 9c 1c [2] e8 04 [2] af 06 [2] e8 17 [2] a6 1b [2] aa 11 [2] bd 1a [2] a6 54 [2] 9b }

  condition:
    any of them
}