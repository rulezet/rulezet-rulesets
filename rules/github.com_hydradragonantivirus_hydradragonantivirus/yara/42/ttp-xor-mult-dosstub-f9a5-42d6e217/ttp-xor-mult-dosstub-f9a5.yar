rule TTP_XOR_MULT_DOSStub_f9a5 {
  strings:
    $key_f9a5 = { ad cd [2] d9 d5 [2] 9e d7 [2] d9 c6 [2] 97 ca [2] 9b c0 [2] 8c cb [2] 97 85 [2] aa }

  condition:
    any of them
}