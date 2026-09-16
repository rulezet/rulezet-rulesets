rule TTP_XOR_MULT_DOSStub_00a5 {
  strings:
    $key_00a5 = { 54 cd [2] 20 d5 [2] 67 d7 [2] 20 c6 [2] 6e ca [2] 62 c0 [2] 75 cb [2] 6e 85 [2] 53 }

  condition:
    any of them
}