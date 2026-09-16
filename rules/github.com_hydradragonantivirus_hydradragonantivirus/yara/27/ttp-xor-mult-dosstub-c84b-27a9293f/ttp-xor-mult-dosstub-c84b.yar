rule TTP_XOR_MULT_DOSStub_c84b {
  strings:
    $key_c84b = { 9c 23 [2] e8 3b [2] af 39 [2] e8 28 [2] a6 24 [2] aa 2e [2] bd 25 [2] a6 6b [2] 9b }

  condition:
    any of them
}