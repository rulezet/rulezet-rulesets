rule TTP_XOR_MULT_DOSStub_e7a5 {
  strings:
    $key_e7a5 = { b3 cd [2] c7 d5 [2] 80 d7 [2] c7 c6 [2] 89 ca [2] 85 c0 [2] 92 cb [2] 89 85 [2] b4 }

  condition:
    any of them
}