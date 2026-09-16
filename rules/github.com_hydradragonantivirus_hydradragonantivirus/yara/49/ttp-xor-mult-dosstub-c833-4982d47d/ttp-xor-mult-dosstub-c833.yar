rule TTP_XOR_MULT_DOSStub_c833 {
  strings:
    $key_c833 = { 9c 5b [2] e8 43 [2] af 41 [2] e8 50 [2] a6 5c [2] aa 56 [2] bd 5d [2] a6 13 [2] 9b }

  condition:
    any of them
}