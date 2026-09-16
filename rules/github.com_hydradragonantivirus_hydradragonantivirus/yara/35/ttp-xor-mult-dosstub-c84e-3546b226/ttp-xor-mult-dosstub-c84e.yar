rule TTP_XOR_MULT_DOSStub_c84e {
  strings:
    $key_c84e = { 9c 26 [2] e8 3e [2] af 3c [2] e8 2d [2] a6 21 [2] aa 2b [2] bd 20 [2] a6 6e [2] 9b }

  condition:
    any of them
}