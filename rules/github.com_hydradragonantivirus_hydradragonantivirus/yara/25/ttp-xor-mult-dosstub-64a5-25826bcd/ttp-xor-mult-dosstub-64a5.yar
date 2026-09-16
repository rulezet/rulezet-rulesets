rule TTP_XOR_MULT_DOSStub_64a5 {
  strings:
    $key_64a5 = { 30 cd [2] 44 d5 [2] 03 d7 [2] 44 c6 [2] 0a ca [2] 06 c0 [2] 11 cb [2] 0a 85 [2] 37 }

  condition:
    any of them
}