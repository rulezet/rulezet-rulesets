rule TTP_XOR_MULT_DOSStub_078a {
  strings:
    $key_078a = { 53 e2 [2] 27 fa [2] 60 f8 [2] 27 e9 [2] 69 e5 [2] 65 ef [2] 72 e4 [2] 69 aa [2] 54 }

  condition:
    any of them
}