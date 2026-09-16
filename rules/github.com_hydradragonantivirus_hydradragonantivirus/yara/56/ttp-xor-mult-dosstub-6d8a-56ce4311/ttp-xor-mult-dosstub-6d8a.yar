rule TTP_XOR_MULT_DOSStub_6d8a {
  strings:
    $key_6d8a = { 39 e2 [2] 4d fa [2] 0a f8 [2] 4d e9 [2] 03 e5 [2] 0f ef [2] 18 e4 [2] 03 aa [2] 3e }

  condition:
    any of them
}