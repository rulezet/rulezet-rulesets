rule TTP_XOR_MULT_DOSStub_50a5 {
  strings:
    $key_50a5 = { 04 cd [2] 70 d5 [2] 37 d7 [2] 70 c6 [2] 3e ca [2] 32 c0 [2] 25 cb [2] 3e 85 [2] 03 }

  condition:
    any of them
}