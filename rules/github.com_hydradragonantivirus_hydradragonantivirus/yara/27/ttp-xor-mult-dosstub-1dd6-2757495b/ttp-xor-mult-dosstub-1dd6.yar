rule TTP_XOR_MULT_DOSStub_1dd6 {
  strings:
    $key_1dd6 = { 49 be [2] 3d a6 [2] 7a a4 [2] 3d b5 [2] 73 b9 [2] 7f b3 [2] 68 b8 [2] 73 f6 [2] 4e }

  condition:
    any of them
}