rule TTP_XOR_MULT_DOSStub_3fa5 {
  strings:
    $key_3fa5 = { 6b cd [2] 1f d5 [2] 58 d7 [2] 1f c6 [2] 51 ca [2] 5d c0 [2] 4a cb [2] 51 85 [2] 6c }

  condition:
    any of them
}