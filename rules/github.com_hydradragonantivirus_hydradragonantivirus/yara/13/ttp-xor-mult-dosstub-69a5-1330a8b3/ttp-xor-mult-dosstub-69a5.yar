rule TTP_XOR_MULT_DOSStub_69a5 {
  strings:
    $key_69a5 = { 3d cd [2] 49 d5 [2] 0e d7 [2] 49 c6 [2] 07 ca [2] 0b c0 [2] 1c cb [2] 07 85 [2] 3a }

  condition:
    any of them
}