rule TTP_XOR_MULT_DOSStub_068a {
  strings:
    $key_068a = { 52 e2 [2] 26 fa [2] 61 f8 [2] 26 e9 [2] 68 e5 [2] 64 ef [2] 73 e4 [2] 68 aa [2] 55 }

  condition:
    any of them
}