rule TTP_XOR_MULT_DOSStub_acda {
  strings:
    $key_acda = { f8 b2 [2] 8c aa [2] cb a8 [2] 8c b9 [2] c2 b5 [2] ce bf [2] d9 b4 [2] c2 fa [2] ff }

  condition:
    any of them
}