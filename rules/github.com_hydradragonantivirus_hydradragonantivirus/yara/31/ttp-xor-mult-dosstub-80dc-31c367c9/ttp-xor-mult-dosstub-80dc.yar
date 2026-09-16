rule TTP_XOR_MULT_DOSStub_80dc {
  strings:
    $key_80dc = { d4 b4 [2] a0 ac [2] e7 ae [2] a0 bf [2] ee b3 [2] e2 b9 [2] f5 b2 [2] ee fc [2] d3 }

  condition:
    any of them
}