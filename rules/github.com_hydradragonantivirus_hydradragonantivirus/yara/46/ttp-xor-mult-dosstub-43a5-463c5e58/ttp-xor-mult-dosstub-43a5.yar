rule TTP_XOR_MULT_DOSStub_43a5 {
  strings:
    $key_43a5 = { 17 cd [2] 63 d5 [2] 24 d7 [2] 63 c6 [2] 2d ca [2] 21 c0 [2] 36 cb [2] 2d 85 [2] 10 }

  condition:
    any of them
}