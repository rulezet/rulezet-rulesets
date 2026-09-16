rule TTP_XOR_MULT_DOSStub_c8e9 {
  strings:
    $key_c8e9 = { 9c 81 [2] e8 99 [2] af 9b [2] e8 8a [2] a6 86 [2] aa 8c [2] bd 87 [2] a6 c9 [2] 9b }

  condition:
    any of them
}