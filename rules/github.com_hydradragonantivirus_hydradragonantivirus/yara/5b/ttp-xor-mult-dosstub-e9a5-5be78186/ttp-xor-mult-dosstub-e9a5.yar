rule TTP_XOR_MULT_DOSStub_e9a5 {
  strings:
    $key_e9a5 = { bd cd [2] c9 d5 [2] 8e d7 [2] c9 c6 [2] 87 ca [2] 8b c0 [2] 9c cb [2] 87 85 [2] ba }

  condition:
    any of them
}