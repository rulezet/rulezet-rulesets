rule TTP_XOR_MULT_DOSStub_c84a {
  strings:
    $key_c84a = { 9c 22 [2] e8 3a [2] af 38 [2] e8 29 [2] a6 25 [2] aa 2f [2] bd 24 [2] a6 6a [2] 9b }

  condition:
    any of them
}