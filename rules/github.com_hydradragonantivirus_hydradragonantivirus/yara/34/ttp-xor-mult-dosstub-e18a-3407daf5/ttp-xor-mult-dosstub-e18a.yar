rule TTP_XOR_MULT_DOSStub_e18a {
  strings:
    $key_e18a = { b5 e2 [2] c1 fa [2] 86 f8 [2] c1 e9 [2] 8f e5 [2] 83 ef [2] 94 e4 [2] 8f aa [2] b2 }

  condition:
    any of them
}