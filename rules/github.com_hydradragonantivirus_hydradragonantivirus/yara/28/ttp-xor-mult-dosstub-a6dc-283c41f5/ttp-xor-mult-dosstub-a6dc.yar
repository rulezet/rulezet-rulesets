rule TTP_XOR_MULT_DOSStub_a6dc {
  strings:
    $key_a6dc = { f2 b4 [2] 86 ac [2] c1 ae [2] 86 bf [2] c8 b3 [2] c4 b9 [2] d3 b2 [2] c8 fc [2] f5 }

  condition:
    any of them
}