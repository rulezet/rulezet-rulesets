rule TTP_XOR_MULT_DOSStub_ebd0 {
  strings:
    $key_ebd0 = { bf b8 [2] cb a0 [2] 8c a2 [2] cb b3 [2] 85 bf [2] 89 b5 [2] 9e be [2] 85 f0 [2] b8 }

  condition:
    any of them
}