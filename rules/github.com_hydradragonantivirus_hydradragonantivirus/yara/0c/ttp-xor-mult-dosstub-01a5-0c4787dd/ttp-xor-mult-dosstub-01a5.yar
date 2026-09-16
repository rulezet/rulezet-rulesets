rule TTP_XOR_MULT_DOSStub_01a5 {
  strings:
    $key_01a5 = { 55 cd [2] 21 d5 [2] 66 d7 [2] 21 c6 [2] 6f ca [2] 63 c0 [2] 74 cb [2] 6f 85 [2] 52 }

  condition:
    any of them
}