rule TTP_XOR_MULT_DOSStub_c8e8 {
  strings:
    $key_c8e8 = { 9c 80 [2] e8 98 [2] af 9a [2] e8 8b [2] a6 87 [2] aa 8d [2] bd 86 [2] a6 c8 [2] 9b }

  condition:
    any of them
}