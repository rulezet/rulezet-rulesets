rule TTP_XOR_MULT_DOSStub_0bdd {
  strings:
    $key_0bdd = { 5f b5 [2] 2b ad [2] 6c af [2] 2b be [2] 65 b2 [2] 69 b8 [2] 7e b3 [2] 65 fd [2] 58 }

  condition:
    any of them
}