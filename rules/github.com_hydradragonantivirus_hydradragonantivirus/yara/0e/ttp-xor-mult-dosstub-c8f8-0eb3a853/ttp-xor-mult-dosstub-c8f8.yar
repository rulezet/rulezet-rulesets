rule TTP_XOR_MULT_DOSStub_c8f8 {
  strings:
    $key_c8f8 = { 9c 90 [2] e8 88 [2] af 8a [2] e8 9b [2] a6 97 [2] aa 9d [2] bd 96 [2] a6 d8 [2] 9b }

  condition:
    any of them
}