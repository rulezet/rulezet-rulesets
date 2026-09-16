rule TTP_XOR_MULT_DOSStub_c84f {
  strings:
    $key_c84f = { 9c 27 [2] e8 3f [2] af 3d [2] e8 2c [2] a6 20 [2] aa 2a [2] bd 21 [2] a6 6f [2] 9b }

  condition:
    any of them
}