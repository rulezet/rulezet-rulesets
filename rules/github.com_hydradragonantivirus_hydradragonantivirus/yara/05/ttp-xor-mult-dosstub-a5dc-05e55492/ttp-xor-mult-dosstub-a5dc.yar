rule TTP_XOR_MULT_DOSStub_a5dc {
  strings:
    $key_a5dc = { f1 b4 [2] 85 ac [2] c2 ae [2] 85 bf [2] cb b3 [2] c7 b9 [2] d0 b2 [2] cb fc [2] f6 }

  condition:
    any of them
}