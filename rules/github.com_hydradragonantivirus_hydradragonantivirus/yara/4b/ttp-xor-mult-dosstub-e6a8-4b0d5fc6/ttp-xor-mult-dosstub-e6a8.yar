rule TTP_XOR_MULT_DOSStub_e6a8 {
  strings:
    $key_e6a8 = { b2 c0 [2] c6 d8 [2] 81 da [2] c6 cb [2] 88 c7 [2] 84 cd [2] 93 c6 [2] 88 88 [2] b5 }

  condition:
    any of them
}