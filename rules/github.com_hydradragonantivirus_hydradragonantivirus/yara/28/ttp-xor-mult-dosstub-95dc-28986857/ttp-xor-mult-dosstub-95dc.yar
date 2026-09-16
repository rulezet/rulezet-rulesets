rule TTP_XOR_MULT_DOSStub_95dc {
  strings:
    $key_95dc = { c1 b4 [2] b5 ac [2] f2 ae [2] b5 bf [2] fb b3 [2] f7 b9 [2] e0 b2 [2] fb fc [2] c6 }

  condition:
    any of them
}