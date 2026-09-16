rule TTP_XOR_MULT_DOSStub_70a5 {
  strings:
    $key_70a5 = { 24 cd [2] 50 d5 [2] 17 d7 [2] 50 c6 [2] 1e ca [2] 12 c0 [2] 05 cb [2] 1e 85 [2] 23 }

  condition:
    any of them
}