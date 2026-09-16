rule TTP_XOR_MULT_DOSStub_14a5 {
  strings:
    $key_14a5 = { 40 cd [2] 34 d5 [2] 73 d7 [2] 34 c6 [2] 7a ca [2] 76 c0 [2] 61 cb [2] 7a 85 [2] 47 }

  condition:
    any of them
}