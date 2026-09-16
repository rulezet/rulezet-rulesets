rule TTP_XOR_MULT_DOSStub_e38a {
  strings:
    $key_e38a = { b7 e2 [2] c3 fa [2] 84 f8 [2] c3 e9 [2] 8d e5 [2] 81 ef [2] 96 e4 [2] 8d aa [2] b0 }

  condition:
    any of them
}