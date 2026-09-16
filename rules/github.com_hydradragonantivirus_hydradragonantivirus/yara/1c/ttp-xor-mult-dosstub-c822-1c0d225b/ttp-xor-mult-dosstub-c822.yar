rule TTP_XOR_MULT_DOSStub_c822 {
  strings:
    $key_c822 = { 9c 4a [2] e8 52 [2] af 50 [2] e8 41 [2] a6 4d [2] aa 47 [2] bd 4c [2] a6 02 [2] 9b }

  condition:
    any of them
}