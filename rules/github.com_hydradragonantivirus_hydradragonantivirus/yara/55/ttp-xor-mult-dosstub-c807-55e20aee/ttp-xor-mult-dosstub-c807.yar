rule TTP_XOR_MULT_DOSStub_c807 {
  strings:
    $key_c807 = { 9c 6f [2] e8 77 [2] af 75 [2] e8 64 [2] a6 68 [2] aa 62 [2] bd 69 [2] a6 27 [2] 9b }

  condition:
    any of them
}