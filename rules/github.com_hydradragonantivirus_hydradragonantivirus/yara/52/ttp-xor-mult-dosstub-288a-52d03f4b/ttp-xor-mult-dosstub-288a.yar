rule TTP_XOR_MULT_DOSStub_288a {
  strings:
    $key_288a = { 7c e2 [2] 08 fa [2] 4f f8 [2] 08 e9 [2] 46 e5 [2] 4a ef [2] 5d e4 [2] 46 aa [2] 7b }

  condition:
    any of them
}