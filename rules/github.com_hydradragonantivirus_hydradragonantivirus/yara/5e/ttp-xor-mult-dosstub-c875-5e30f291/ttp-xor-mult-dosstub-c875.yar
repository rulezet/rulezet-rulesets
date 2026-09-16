rule TTP_XOR_MULT_DOSStub_c875 {
  strings:
    $key_c875 = { 9c 1d [2] e8 05 [2] af 07 [2] e8 16 [2] a6 1a [2] aa 10 [2] bd 1b [2] a6 55 [2] 9b }

  condition:
    any of them
}