rule TTP_XOR_MULT_DOSStub_35a5 {
  strings:
    $key_35a5 = { 61 cd [2] 15 d5 [2] 52 d7 [2] 15 c6 [2] 5b ca [2] 57 c0 [2] 40 cb [2] 5b 85 [2] 66 }

  condition:
    any of them
}