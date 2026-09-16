rule TTP_XOR_MULT_DOSStub_e6a5 {
  strings:
    $key_e6a5 = { b2 cd [2] c6 d5 [2] 81 d7 [2] c6 c6 [2] 88 ca [2] 84 c0 [2] 93 cb [2] 88 85 [2] b5 }

  condition:
    any of them
}