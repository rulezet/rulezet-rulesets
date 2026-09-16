rule TTP_XOR_MULT_DOSStub_acdd {
  strings:
    $key_acdd = { f8 b5 [2] 8c ad [2] cb af [2] 8c be [2] c2 b2 [2] ce b8 [2] d9 b3 [2] c2 fd [2] ff }

  condition:
    any of them
}