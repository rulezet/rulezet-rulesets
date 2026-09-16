rule TTP_XOR_MULT_DOSStub_ac9a {
  strings:
    $key_ac9a = { f8 f2 [2] 8c ea [2] cb e8 [2] 8c f9 [2] c2 f5 [2] ce ff [2] d9 f4 [2] c2 ba [2] ff }

  condition:
    any of them
}