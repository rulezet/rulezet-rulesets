rule TTP_XOR_MULT_DOSStub_e5a8 {
  strings:
    $key_e5a8 = { b1 c0 [2] c5 d8 [2] 82 da [2] c5 cb [2] 8b c7 [2] 87 cd [2] 90 c6 [2] 8b 88 [2] b6 }

  condition:
    any of them
}