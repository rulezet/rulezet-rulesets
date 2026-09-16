rule TTP_XOR_MULT_DOSStub_5fa5 {
  strings:
    $key_5fa5 = { 0b cd [2] 7f d5 [2] 38 d7 [2] 7f c6 [2] 31 ca [2] 3d c0 [2] 2a cb [2] 31 85 [2] 0c }

  condition:
    any of them
}