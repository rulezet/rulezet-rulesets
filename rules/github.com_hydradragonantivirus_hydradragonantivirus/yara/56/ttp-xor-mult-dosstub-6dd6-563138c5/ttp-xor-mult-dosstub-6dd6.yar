rule TTP_XOR_MULT_DOSStub_6dd6 {
  strings:
    $key_6dd6 = { 39 be [2] 4d a6 [2] 0a a4 [2] 4d b5 [2] 03 b9 [2] 0f b3 [2] 18 b8 [2] 03 f6 [2] 3e }

  condition:
    any of them
}