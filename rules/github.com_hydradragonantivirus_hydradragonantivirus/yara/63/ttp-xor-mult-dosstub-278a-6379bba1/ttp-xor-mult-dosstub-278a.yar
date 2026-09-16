rule TTP_XOR_MULT_DOSStub_278a {
  strings:
    $key_278a = { 73 e2 [2] 07 fa [2] 40 f8 [2] 07 e9 [2] 49 e5 [2] 45 ef [2] 52 e4 [2] 49 aa [2] 74 }

  condition:
    any of them
}