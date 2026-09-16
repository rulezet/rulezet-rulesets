rule TTP_XOR_MULT_DOSStub_c80b {
  strings:
    $key_c80b = { 9c 63 [2] e8 7b [2] af 79 [2] e8 68 [2] a6 64 [2] aa 6e [2] bd 65 [2] a6 2b [2] 9b }

  condition:
    any of them
}