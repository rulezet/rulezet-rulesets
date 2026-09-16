rule TTP_XOR_MULT_DOSStub_44a5 {
  strings:
    $key_44a5 = { 10 cd [2] 64 d5 [2] 23 d7 [2] 64 c6 [2] 2a ca [2] 26 c0 [2] 31 cb [2] 2a 85 [2] 17 }

  condition:
    any of them
}