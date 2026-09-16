rule TTP_XOR_MULT_DOSStub_78ae {
  strings:
    $key_78ae = { 2c c6 [2] 58 de [2] 1f dc [2] 58 cd [2] 16 c1 [2] 1a cb [2] 0d c0 [2] 16 8e [2] 2b }

  condition:
    any of them
}