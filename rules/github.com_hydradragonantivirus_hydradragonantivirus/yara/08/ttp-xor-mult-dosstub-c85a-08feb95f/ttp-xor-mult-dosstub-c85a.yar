rule TTP_XOR_MULT_DOSStub_c85a {
  strings:
    $key_c85a = { 9c 32 [2] e8 2a [2] af 28 [2] e8 39 [2] a6 35 [2] aa 3f [2] bd 34 [2] a6 7a [2] 9b }

  condition:
    any of them
}