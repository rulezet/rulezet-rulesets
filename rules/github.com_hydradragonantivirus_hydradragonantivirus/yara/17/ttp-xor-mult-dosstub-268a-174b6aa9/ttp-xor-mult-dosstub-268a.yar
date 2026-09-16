rule TTP_XOR_MULT_DOSStub_268a {
  strings:
    $key_268a = { 72 e2 [2] 06 fa [2] 41 f8 [2] 06 e9 [2] 48 e5 [2] 44 ef [2] 53 e4 [2] 48 aa [2] 75 }

  condition:
    any of them
}