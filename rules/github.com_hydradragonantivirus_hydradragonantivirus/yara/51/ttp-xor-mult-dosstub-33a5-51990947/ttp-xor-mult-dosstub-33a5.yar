rule TTP_XOR_MULT_DOSStub_33a5 {
  strings:
    $key_33a5 = { 67 cd [2] 13 d5 [2] 54 d7 [2] 13 c6 [2] 5d ca [2] 51 c0 [2] 46 cb [2] 5d 85 [2] 60 }

  condition:
    any of them
}