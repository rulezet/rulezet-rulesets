rule TTP_XOR_MULT_DOSStub_71a5 {
  strings:
    $key_71a5 = { 25 cd [2] 51 d5 [2] 16 d7 [2] 51 c6 [2] 1f ca [2] 13 c0 [2] 04 cb [2] 1f 85 [2] 22 }

  condition:
    any of them
}