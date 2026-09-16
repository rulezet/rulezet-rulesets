rule TTP_XOR_MULT_DOSStub_b3a8 {
  strings:
    $key_b3a8 = { e7 c0 [2] 93 d8 [2] d4 da [2] 93 cb [2] dd c7 [2] d1 cd [2] c6 c6 [2] dd 88 [2] e0 }

  condition:
    any of them
}