rule TTP_XOR_MULT_DOSStub_ac8f {
  strings:
    $key_ac8f = { f8 e7 [2] 8c ff [2] cb fd [2] 8c ec [2] c2 e0 [2] ce ea [2] d9 e1 [2] c2 af [2] ff }

  condition:
    any of them
}