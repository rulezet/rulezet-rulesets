rule TTP_XOR_MULT_DOSStub_ac8a {
  strings:
    $key_ac8a = { f8 e2 [2] 8c fa [2] cb f8 [2] 8c e9 [2] c2 e5 [2] ce ef [2] d9 e4 [2] c2 aa [2] ff }

  condition:
    any of them
}