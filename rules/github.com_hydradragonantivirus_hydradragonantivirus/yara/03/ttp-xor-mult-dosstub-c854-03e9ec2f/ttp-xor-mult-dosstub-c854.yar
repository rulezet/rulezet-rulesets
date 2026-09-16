rule TTP_XOR_MULT_DOSStub_c854 {
  strings:
    $key_c854 = { 9c 3c [2] e8 24 [2] af 26 [2] e8 37 [2] a6 3b [2] aa 31 [2] bd 3a [2] a6 74 [2] 9b }

  condition:
    any of them
}