rule TTP_XOR_MULT_DOSStub_76a5 {
  strings:
    $key_76a5 = { 22 cd [2] 56 d5 [2] 11 d7 [2] 56 c6 [2] 18 ca [2] 14 c0 [2] 03 cb [2] 18 85 [2] 25 }

  condition:
    any of them
}