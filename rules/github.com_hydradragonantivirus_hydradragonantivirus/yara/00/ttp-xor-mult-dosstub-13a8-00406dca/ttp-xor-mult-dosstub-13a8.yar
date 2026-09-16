rule TTP_XOR_MULT_DOSStub_13a8 {
  strings:
    $key_13a8 = { 47 c0 [2] 33 d8 [2] 74 da [2] 33 cb [2] 7d c7 [2] 71 cd [2] 66 c6 [2] 7d 88 [2] 40 }

  condition:
    any of them
}