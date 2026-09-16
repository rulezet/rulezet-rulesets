rule TTP_XOR_MULT_DOSStub_c83b {
  strings:
    $key_c83b = { 9c 53 [2] e8 4b [2] af 49 [2] e8 58 [2] a6 54 [2] aa 5e [2] bd 55 [2] a6 1b [2] 9b }

  condition:
    any of them
}