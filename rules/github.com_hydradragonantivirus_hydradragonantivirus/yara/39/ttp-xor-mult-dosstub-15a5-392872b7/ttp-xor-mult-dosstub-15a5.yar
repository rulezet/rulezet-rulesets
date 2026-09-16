rule TTP_XOR_MULT_DOSStub_15a5 {
  strings:
    $key_15a5 = { 41 cd [2] 35 d5 [2] 72 d7 [2] 35 c6 [2] 7b ca [2] 77 c0 [2] 60 cb [2] 7b 85 [2] 46 }

  condition:
    any of them
}