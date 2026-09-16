rule TTP_XOR_MULT_DOSStub_32a5 {
  strings:
    $key_32a5 = { 66 cd [2] 12 d5 [2] 55 d7 [2] 12 c6 [2] 5c ca [2] 50 c0 [2] 47 cb [2] 5c 85 [2] 61 }

  condition:
    any of them
}