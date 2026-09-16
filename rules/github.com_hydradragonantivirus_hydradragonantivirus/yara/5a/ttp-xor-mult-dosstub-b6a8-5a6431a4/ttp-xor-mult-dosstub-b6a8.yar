rule TTP_XOR_MULT_DOSStub_b6a8 {
  strings:
    $key_b6a8 = { e2 c0 [2] 96 d8 [2] d1 da [2] 96 cb [2] d8 c7 [2] d4 cd [2] c3 c6 [2] d8 88 [2] e5 }

  condition:
    any of them
}