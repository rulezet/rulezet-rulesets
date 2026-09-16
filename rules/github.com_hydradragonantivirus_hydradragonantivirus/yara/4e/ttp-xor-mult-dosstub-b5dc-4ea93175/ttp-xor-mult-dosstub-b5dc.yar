rule TTP_XOR_MULT_DOSStub_b5dc {
  strings:
    $key_b5dc = { e1 b4 [2] 95 ac [2] d2 ae [2] 95 bf [2] db b3 [2] d7 b9 [2] c0 b2 [2] db fc [2] e6 }

  condition:
    any of them
}