rule TTP_XOR_MULT_DOSStub_e4a5 {
  strings:
    $key_e4a5 = { b0 cd [2] c4 d5 [2] 83 d7 [2] c4 c6 [2] 8a ca [2] 86 c0 [2] 91 cb [2] 8a 85 [2] b7 }

  condition:
    any of them
}