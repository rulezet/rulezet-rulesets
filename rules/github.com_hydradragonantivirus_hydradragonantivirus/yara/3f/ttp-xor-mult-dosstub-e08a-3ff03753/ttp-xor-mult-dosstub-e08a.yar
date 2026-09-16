rule TTP_XOR_MULT_DOSStub_e08a {
  strings:
    $key_e08a = { b4 e2 [2] c0 fa [2] 87 f8 [2] c0 e9 [2] 8e e5 [2] 82 ef [2] 95 e4 [2] 8e aa [2] b3 }

  condition:
    any of them
}