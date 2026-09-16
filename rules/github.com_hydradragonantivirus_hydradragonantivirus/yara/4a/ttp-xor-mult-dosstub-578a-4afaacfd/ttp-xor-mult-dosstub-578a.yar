rule TTP_XOR_MULT_DOSStub_578a {
  strings:
    $key_578a = { 03 e2 [2] 77 fa [2] 30 f8 [2] 77 e9 [2] 39 e5 [2] 35 ef [2] 22 e4 [2] 39 aa [2] 04 }

  condition:
    any of them
}