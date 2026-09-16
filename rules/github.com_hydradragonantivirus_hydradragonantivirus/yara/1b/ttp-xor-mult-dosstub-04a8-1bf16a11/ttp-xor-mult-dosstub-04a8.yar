rule TTP_XOR_MULT_DOSStub_04a8 {
  strings:
    $key_04a8 = { 50 c0 [2] 24 d8 [2] 63 da [2] 24 cb [2] 6a c7 [2] 66 cd [2] 71 c6 [2] 6a 88 [2] 57 }

  condition:
    any of them
}