rule TTP_XOR_MULT_DOSStub_77a5 {
  strings:
    $key_77a5 = { 23 cd [2] 57 d5 [2] 10 d7 [2] 57 c6 [2] 19 ca [2] 15 c0 [2] 02 cb [2] 19 85 [2] 24 }

  condition:
    any of them
}