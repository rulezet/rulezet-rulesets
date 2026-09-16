rule TTP_XOR_MULT_DOSStub_71a8 {
  strings:
    $key_71a8 = { 25 c0 [2] 51 d8 [2] 16 da [2] 51 cb [2] 1f c7 [2] 13 cd [2] 04 c6 [2] 1f 88 [2] 22 }

  condition:
    any of them
}