rule TTP_XOR_MULT_DOSStub_c81d {
  strings:
    $key_c81d = { 9c 75 [2] e8 6d [2] af 6f [2] e8 7e [2] a6 72 [2] aa 78 [2] bd 73 [2] a6 3d [2] 9b }

  condition:
    any of them
}