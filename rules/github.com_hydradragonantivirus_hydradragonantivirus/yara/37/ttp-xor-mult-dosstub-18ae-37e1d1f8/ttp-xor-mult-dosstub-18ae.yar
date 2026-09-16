rule TTP_XOR_MULT_DOSStub_18ae {
  strings:
    $key_18ae = { 4c c6 [2] 38 de [2] 7f dc [2] 38 cd [2] 76 c1 [2] 7a cb [2] 6d c0 [2] 76 8e [2] 4b }

  condition:
    any of them
}