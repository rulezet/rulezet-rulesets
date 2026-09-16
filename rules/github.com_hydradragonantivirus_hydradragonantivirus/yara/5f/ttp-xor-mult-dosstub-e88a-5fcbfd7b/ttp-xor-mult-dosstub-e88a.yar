rule TTP_XOR_MULT_DOSStub_e88a {
  strings:
    $key_e88a = { bc e2 [2] c8 fa [2] 8f f8 [2] c8 e9 [2] 86 e5 [2] 8a ef [2] 9d e4 [2] 86 aa [2] bb }

  condition:
    any of them
}