rule TTP_XOR_MULT_DOSStub_e78a {
  strings:
    $key_e78a = { b3 e2 [2] c7 fa [2] 80 f8 [2] c7 e9 [2] 89 e5 [2] 85 ef [2] 92 e4 [2] 89 aa [2] b4 }

  condition:
    any of them
}