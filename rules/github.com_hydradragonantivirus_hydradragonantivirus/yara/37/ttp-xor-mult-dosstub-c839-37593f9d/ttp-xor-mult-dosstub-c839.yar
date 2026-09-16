rule TTP_XOR_MULT_DOSStub_c839 {
  strings:
    $key_c839 = { 9c 51 [2] e8 49 [2] af 4b [2] e8 5a [2] a6 56 [2] aa 5c [2] bd 57 [2] a6 19 [2] 9b }

  condition:
    any of them
}