rule TTP_XOR_MULT_DOSStub_4aa5 {
  strings:
    $key_4aa5 = { 1e cd [2] 6a d5 [2] 2d d7 [2] 6a c6 [2] 24 ca [2] 28 c0 [2] 3f cb [2] 24 85 [2] 19 }

  condition:
    any of them
}