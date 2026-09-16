rule TTP_XOR_MULT_DOSStub_51a8 {
  strings:
    $key_51a8 = { 05 c0 [2] 71 d8 [2] 36 da [2] 71 cb [2] 3f c7 [2] 33 cd [2] 24 c6 [2] 3f 88 [2] 02 }

  condition:
    any of them
}