rule TTP_XOR_MULT_DOSStub_5bdd {
  strings:
    $key_5bdd = { 0f b5 [2] 7b ad [2] 3c af [2] 7b be [2] 35 b2 [2] 39 b8 [2] 2e b3 [2] 35 fd [2] 08 }

  condition:
    any of them
}