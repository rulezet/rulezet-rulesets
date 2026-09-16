rule TTP_XOR_MULT_DOSStub_c816 {
  strings:
    $key_c816 = { 9c 7e [2] e8 66 [2] af 64 [2] e8 75 [2] a6 79 [2] aa 73 [2] bd 78 [2] a6 36 [2] 9b }

  condition:
    any of them
}