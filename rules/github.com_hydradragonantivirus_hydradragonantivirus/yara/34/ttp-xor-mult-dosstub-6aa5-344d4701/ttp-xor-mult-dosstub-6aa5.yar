rule TTP_XOR_MULT_DOSStub_6aa5 {
  strings:
    $key_6aa5 = { 3e cd [2] 4a d5 [2] 0d d7 [2] 4a c6 [2] 04 ca [2] 08 c0 [2] 1f cb [2] 04 85 [2] 39 }

  condition:
    any of them
}