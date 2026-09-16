rule TTP_XOR_MULT_DOSStub_85dc {
  strings:
    $key_85dc = { d1 b4 [2] a5 ac [2] e2 ae [2] a5 bf [2] eb b3 [2] e7 b9 [2] f0 b2 [2] eb fc [2] d6 }

  condition:
    any of them
}