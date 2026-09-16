rule TTP_XOR_MULT_DOSStub_91dc {
  strings:
    $key_91dc = { c5 b4 [2] b1 ac [2] f6 ae [2] b1 bf [2] ff b3 [2] f3 b9 [2] e4 b2 [2] ff fc [2] c2 }

  condition:
    any of them
}