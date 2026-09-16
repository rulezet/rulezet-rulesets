rule TTP_XOR_MULT_DOSStub_60a5 {
  strings:
    $key_60a5 = { 34 cd [2] 40 d5 [2] 07 d7 [2] 40 c6 [2] 0e ca [2] 02 c0 [2] 15 cb [2] 0e 85 [2] 33 }

  condition:
    any of them
}