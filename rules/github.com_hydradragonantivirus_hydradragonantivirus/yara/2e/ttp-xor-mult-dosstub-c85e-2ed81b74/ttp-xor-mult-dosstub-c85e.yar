rule TTP_XOR_MULT_DOSStub_c85e {
  strings:
    $key_c85e = { 9c 36 [2] e8 2e [2] af 2c [2] e8 3d [2] a6 31 [2] aa 3b [2] bd 30 [2] a6 7e [2] 9b }

  condition:
    any of them
}