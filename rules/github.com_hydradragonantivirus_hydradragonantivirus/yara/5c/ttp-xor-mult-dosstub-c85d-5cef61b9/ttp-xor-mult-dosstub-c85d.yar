rule TTP_XOR_MULT_DOSStub_c85d {
  strings:
    $key_c85d = { 9c 35 [2] e8 2d [2] af 2f [2] e8 3e [2] a6 32 [2] aa 38 [2] bd 33 [2] a6 7d [2] 9b }

  condition:
    any of them
}