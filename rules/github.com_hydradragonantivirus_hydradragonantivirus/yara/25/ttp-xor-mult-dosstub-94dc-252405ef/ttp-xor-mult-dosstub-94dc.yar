rule TTP_XOR_MULT_DOSStub_94dc {
  strings:
    $key_94dc = { c0 b4 [2] b4 ac [2] f3 ae [2] b4 bf [2] fa b3 [2] f6 b9 [2] e1 b2 [2] fa fc [2] c7 }

  condition:
    any of them
}