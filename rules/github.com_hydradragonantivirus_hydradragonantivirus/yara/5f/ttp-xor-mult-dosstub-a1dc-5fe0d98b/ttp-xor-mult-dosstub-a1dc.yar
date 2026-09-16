rule TTP_XOR_MULT_DOSStub_a1dc {
  strings:
    $key_a1dc = { f5 b4 [2] 81 ac [2] c6 ae [2] 81 bf [2] cf b3 [2] c3 b9 [2] d4 b2 [2] cf fc [2] f2 }

  condition:
    any of them
}