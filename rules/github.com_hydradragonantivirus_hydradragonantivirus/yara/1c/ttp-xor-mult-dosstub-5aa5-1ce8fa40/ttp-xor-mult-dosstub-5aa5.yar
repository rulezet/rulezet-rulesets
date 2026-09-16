rule TTP_XOR_MULT_DOSStub_5aa5 {
  strings:
    $key_5aa5 = { 0e cd [2] 7a d5 [2] 3d d7 [2] 7a c6 [2] 34 ca [2] 38 c0 [2] 2f cb [2] 34 85 [2] 09 }

  condition:
    any of them
}