rule TTP_XOR_MULT_DOSStub_e0a5 {
  strings:
    $key_e0a5 = { b4 cd [2] c0 d5 [2] 87 d7 [2] c0 c6 [2] 8e ca [2] 82 c0 [2] 95 cb [2] 8e 85 [2] b3 }

  condition:
    any of them
}