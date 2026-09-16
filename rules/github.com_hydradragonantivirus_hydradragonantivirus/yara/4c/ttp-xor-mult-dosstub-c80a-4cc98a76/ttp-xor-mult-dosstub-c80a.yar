rule TTP_XOR_MULT_DOSStub_c80a {
  strings:
    $key_c80a = { 9c 62 [2] e8 7a [2] af 78 [2] e8 69 [2] a6 65 [2] aa 6f [2] bd 64 [2] a6 2a [2] 9b }

  condition:
    any of them
}