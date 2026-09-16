rule TTP_XOR_MULT_DOSStub_c86f {
  strings:
    $key_c86f = { 9c 07 [2] e8 1f [2] af 1d [2] e8 0c [2] a6 00 [2] aa 0a [2] bd 01 [2] a6 4f [2] 9b }

  condition:
    any of them
}