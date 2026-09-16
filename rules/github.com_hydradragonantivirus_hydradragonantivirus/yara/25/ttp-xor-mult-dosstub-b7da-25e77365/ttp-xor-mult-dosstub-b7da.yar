rule TTP_XOR_MULT_DOSStub_b7da {
  strings:
    $key_b7da = { e3 b2 [2] 97 aa [2] d0 a8 [2] 97 b9 [2] d9 b5 [2] d5 bf [2] c2 b4 [2] d9 fa [2] e4 }

  condition:
    any of them
}