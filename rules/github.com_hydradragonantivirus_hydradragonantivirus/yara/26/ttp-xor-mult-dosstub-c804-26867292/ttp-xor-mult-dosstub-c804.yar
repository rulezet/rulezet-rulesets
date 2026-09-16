rule TTP_XOR_MULT_DOSStub_c804 {
  strings:
    $key_c804 = { 9c 6c [2] e8 74 [2] af 76 [2] e8 67 [2] a6 6b [2] aa 61 [2] bd 6a [2] a6 24 [2] 9b }

  condition:
    any of them
}