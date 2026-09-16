rule TTP_XOR_MULT_DOSStub_0fa5 {
  strings:
    $key_0fa5 = { 5b cd [2] 2f d5 [2] 68 d7 [2] 2f c6 [2] 61 ca [2] 6d c0 [2] 7a cb [2] 61 85 [2] 5c }

  condition:
    any of them
}