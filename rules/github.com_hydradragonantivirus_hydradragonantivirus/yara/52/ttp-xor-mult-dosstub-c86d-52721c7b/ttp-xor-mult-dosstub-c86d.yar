rule TTP_XOR_MULT_DOSStub_c86d {
  strings:
    $key_c86d = { 9c 05 [2] e8 1d [2] af 1f [2] e8 0e [2] a6 02 [2] aa 08 [2] bd 03 [2] a6 4d [2] 9b }

  condition:
    any of them
}