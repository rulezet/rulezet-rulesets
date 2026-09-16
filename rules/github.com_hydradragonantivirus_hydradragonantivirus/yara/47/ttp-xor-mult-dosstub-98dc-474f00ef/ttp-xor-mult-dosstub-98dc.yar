rule TTP_XOR_MULT_DOSStub_98dc {
  strings:
    $key_98dc = { cc b4 [2] b8 ac [2] ff ae [2] b8 bf [2] f6 b3 [2] fa b9 [2] ed b2 [2] f6 fc [2] cb }

  condition:
    any of them
}