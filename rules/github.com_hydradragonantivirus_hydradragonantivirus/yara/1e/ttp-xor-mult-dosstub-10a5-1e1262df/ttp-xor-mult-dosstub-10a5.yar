rule TTP_XOR_MULT_DOSStub_10a5 {
  strings:
    $key_10a5 = { 44 cd [2] 30 d5 [2] 77 d7 [2] 30 c6 [2] 7e ca [2] 72 c0 [2] 65 cb [2] 7e 85 [2] 43 }

  condition:
    any of them
}