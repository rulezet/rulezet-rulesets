rule TTP_XOR_MULT_DOSStub_38ae {
  strings:
    $key_38ae = { 6c c6 [2] 18 de [2] 5f dc [2] 18 cd [2] 56 c1 [2] 5a cb [2] 4d c0 [2] 56 8e [2] 6b }

  condition:
    any of them
}