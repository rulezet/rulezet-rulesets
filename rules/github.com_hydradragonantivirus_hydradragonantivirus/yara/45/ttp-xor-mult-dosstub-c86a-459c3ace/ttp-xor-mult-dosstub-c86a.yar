rule TTP_XOR_MULT_DOSStub_c86a {
  strings:
    $key_c86a = { 9c 02 [2] e8 1a [2] af 18 [2] e8 09 [2] a6 05 [2] aa 0f [2] bd 04 [2] a6 4a [2] 9b }

  condition:
    any of them
}