rule TTP_XOR_MULT_DOSStub_0aa5 {
  strings:
    $key_0aa5 = { 5e cd [2] 2a d5 [2] 6d d7 [2] 2a c6 [2] 64 ca [2] 68 c0 [2] 7f cb [2] 64 85 [2] 59 }

  condition:
    any of them
}