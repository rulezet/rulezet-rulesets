rule TTP_XOR_MULT_DOSStub_ebdd {
  strings:
    $key_ebdd = { bf b5 [2] cb ad [2] 8c af [2] cb be [2] 85 b2 [2] 89 b8 [2] 9e b3 [2] 85 fd [2] b8 }

  condition:
    any of them
}