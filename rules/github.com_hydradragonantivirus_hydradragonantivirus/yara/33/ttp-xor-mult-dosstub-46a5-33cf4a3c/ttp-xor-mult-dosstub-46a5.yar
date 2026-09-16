rule TTP_XOR_MULT_DOSStub_46a5 {
  strings:
    $key_46a5 = { 12 cd [2] 66 d5 [2] 21 d7 [2] 66 c6 [2] 28 ca [2] 24 c0 [2] 33 cb [2] 28 85 [2] 15 }

  condition:
    any of them
}