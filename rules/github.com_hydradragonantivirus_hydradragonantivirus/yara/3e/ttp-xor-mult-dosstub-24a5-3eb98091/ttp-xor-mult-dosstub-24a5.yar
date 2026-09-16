rule TTP_XOR_MULT_DOSStub_24a5 {
  strings:
    $key_24a5 = { 70 cd [2] 04 d5 [2] 43 d7 [2] 04 c6 [2] 4a ca [2] 46 c0 [2] 51 cb [2] 4a 85 [2] 77 }

  condition:
    any of them
}