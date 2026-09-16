rule TTP_XOR_MULT_DOSStub_27a5 {
  strings:
    $key_27a5 = { 73 cd [2] 07 d5 [2] 40 d7 [2] 07 c6 [2] 49 ca [2] 45 c0 [2] 52 cb [2] 49 85 [2] 74 }

  condition:
    any of them
}