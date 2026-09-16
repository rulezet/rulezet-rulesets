rule TTP_XOR_MULT_DOSStub_c3a8 {
  strings:
    $key_c3a8 = { 97 c0 [2] e3 d8 [2] a4 da [2] e3 cb [2] ad c7 [2] a1 cd [2] b6 c6 [2] ad 88 [2] 90 }

  condition:
    any of them
}