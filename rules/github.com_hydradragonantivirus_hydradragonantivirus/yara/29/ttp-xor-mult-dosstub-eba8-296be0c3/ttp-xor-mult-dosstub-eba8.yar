rule TTP_XOR_MULT_DOSStub_eba8 {
  strings:
    $key_eba8 = { bf c0 [2] cb d8 [2] 8c da [2] cb cb [2] 85 c7 [2] 89 cd [2] 9e c6 [2] 85 88 [2] b8 }

  condition:
    any of them
}