rule TTP_XOR_MULT_DOSStub_c8e4 {
  strings:
    $key_c8e4 = { 9c 8c [2] e8 94 [2] af 96 [2] e8 87 [2] a6 8b [2] aa 81 [2] bd 8a [2] a6 c4 [2] 9b }

  condition:
    any of them
}