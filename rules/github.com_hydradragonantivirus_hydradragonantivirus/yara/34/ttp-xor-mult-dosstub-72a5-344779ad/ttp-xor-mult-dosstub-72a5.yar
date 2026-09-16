rule TTP_XOR_MULT_DOSStub_72a5 {
  strings:
    $key_72a5 = { 26 cd [2] 52 d5 [2] 15 d7 [2] 52 c6 [2] 1c ca [2] 10 c0 [2] 07 cb [2] 1c 85 [2] 21 }

  condition:
    any of them
}