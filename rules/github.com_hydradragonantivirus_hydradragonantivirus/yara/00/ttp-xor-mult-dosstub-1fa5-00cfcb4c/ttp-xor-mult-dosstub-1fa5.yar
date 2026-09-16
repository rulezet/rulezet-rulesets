rule TTP_XOR_MULT_DOSStub_1fa5 {
  strings:
    $key_1fa5 = { 4b cd [2] 3f d5 [2] 78 d7 [2] 3f c6 [2] 71 ca [2] 7d c0 [2] 6a cb [2] 71 85 [2] 4c }

  condition:
    any of them
}