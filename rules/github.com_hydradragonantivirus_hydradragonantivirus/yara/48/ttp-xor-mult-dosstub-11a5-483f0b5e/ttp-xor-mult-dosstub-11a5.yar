rule TTP_XOR_MULT_DOSStub_11a5 {
  strings:
    $key_11a5 = { 45 cd [2] 31 d5 [2] 76 d7 [2] 31 c6 [2] 7f ca [2] 73 c0 [2] 64 cb [2] 7f 85 [2] 42 }

  condition:
    any of them
}