rule TTP_XOR_MULT_DOSStub_c852 {
  strings:
    $key_c852 = { 9c 3a [2] e8 22 [2] af 20 [2] e8 31 [2] a6 3d [2] aa 37 [2] bd 3c [2] a6 72 [2] 9b }

  condition:
    any of them
}