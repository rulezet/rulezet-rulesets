rule TTP_XOR_MULT_DOSStub_c844 {
  strings:
    $key_c844 = { 9c 2c [2] e8 34 [2] af 36 [2] e8 27 [2] a6 2b [2] aa 21 [2] bd 2a [2] a6 64 [2] 9b }

  condition:
    any of them
}