rule TTP_XOR_MULT_DOSStub_36a5 {
  strings:
    $key_36a5 = { 62 cd [2] 16 d5 [2] 51 d7 [2] 16 c6 [2] 58 ca [2] 54 c0 [2] 43 cb [2] 58 85 [2] 65 }

  condition:
    any of them
}