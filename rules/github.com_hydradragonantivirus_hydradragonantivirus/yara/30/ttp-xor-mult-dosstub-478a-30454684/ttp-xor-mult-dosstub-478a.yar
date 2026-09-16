rule TTP_XOR_MULT_DOSStub_478a {
  strings:
    $key_478a = { 13 e2 [2] 67 fa [2] 20 f8 [2] 67 e9 [2] 29 e5 [2] 25 ef [2] 32 e4 [2] 29 aa [2] 14 }

  condition:
    any of them
}