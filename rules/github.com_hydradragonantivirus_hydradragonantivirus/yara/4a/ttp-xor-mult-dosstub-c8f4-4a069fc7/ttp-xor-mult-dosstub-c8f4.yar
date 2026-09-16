rule TTP_XOR_MULT_DOSStub_c8f4 {
  strings:
    $key_c8f4 = { 9c 9c [2] e8 84 [2] af 86 [2] e8 97 [2] a6 9b [2] aa 91 [2] bd 9a [2] a6 d4 [2] 9b }

  condition:
    any of them
}