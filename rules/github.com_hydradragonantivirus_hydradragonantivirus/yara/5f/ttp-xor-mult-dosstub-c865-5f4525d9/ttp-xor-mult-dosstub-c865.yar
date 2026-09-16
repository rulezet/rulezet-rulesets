rule TTP_XOR_MULT_DOSStub_c865 {
  strings:
    $key_c865 = { 9c 0d [2] e8 15 [2] af 17 [2] e8 06 [2] a6 0a [2] aa 00 [2] bd 0b [2] a6 45 [2] 9b }

  condition:
    any of them
}