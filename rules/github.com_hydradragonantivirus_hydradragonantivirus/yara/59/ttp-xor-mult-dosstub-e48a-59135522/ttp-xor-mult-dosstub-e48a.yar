rule TTP_XOR_MULT_DOSStub_e48a {
  strings:
    $key_e48a = { b0 e2 [2] c4 fa [2] 83 f8 [2] c4 e9 [2] 8a e5 [2] 86 ef [2] 91 e4 [2] 8a aa [2] b7 }

  condition:
    any of them
}