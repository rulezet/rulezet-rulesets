rule TTP_XOR_MULT_DOSStub_30a5 {
  strings:
    $key_30a5 = { 64 cd [2] 10 d5 [2] 57 d7 [2] 10 c6 [2] 5e ca [2] 52 c0 [2] 45 cb [2] 5e 85 [2] 63 }

  condition:
    any of them
}