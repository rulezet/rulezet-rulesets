rule TTP_XOR_MULT_DOSStub_4bdd {
  strings:
    $key_4bdd = { 1f b5 [2] 6b ad [2] 2c af [2] 6b be [2] 25 b2 [2] 29 b8 [2] 3e b3 [2] 25 fd [2] 18 }

  condition:
    any of them
}