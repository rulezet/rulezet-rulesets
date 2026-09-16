rule TTP_XOR_MULT_DOSStub_e1a8 {
  strings:
    $key_e1a8 = { b5 c0 [2] c1 d8 [2] 86 da [2] c1 cb [2] 8f c7 [2] 83 cd [2] 94 c6 [2] 8f 88 [2] b2 }

  condition:
    any of them
}