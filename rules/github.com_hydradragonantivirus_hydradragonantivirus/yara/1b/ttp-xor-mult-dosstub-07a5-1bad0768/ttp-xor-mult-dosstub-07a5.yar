rule TTP_XOR_MULT_DOSStub_07a5 {
  strings:
    $key_07a5 = { 53 cd [2] 27 d5 [2] 60 d7 [2] 27 c6 [2] 69 ca [2] 65 c0 [2] 72 cb [2] 69 85 [2] 54 }

  condition:
    any of them
}