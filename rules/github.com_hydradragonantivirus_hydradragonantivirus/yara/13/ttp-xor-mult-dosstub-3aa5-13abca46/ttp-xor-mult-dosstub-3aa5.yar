rule TTP_XOR_MULT_DOSStub_3aa5 {
  strings:
    $key_3aa5 = { 6e cd [2] 1a d5 [2] 5d d7 [2] 1a c6 [2] 54 ca [2] 58 c0 [2] 4f cb [2] 54 85 [2] 69 }

  condition:
    any of them
}