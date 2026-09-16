rule TTP_XOR_MULT_DOSStub_c87a {
  strings:
    $key_c87a = { 9c 12 [2] e8 0a [2] af 08 [2] e8 19 [2] a6 15 [2] aa 1f [2] bd 14 [2] a6 5a [2] 9b }

  condition:
    any of them
}