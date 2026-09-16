rule TTP_XOR_MULT_DOSStub_488a {
  strings:
    $key_488a = { 1c e2 [2] 68 fa [2] 2f f8 [2] 68 e9 [2] 26 e5 [2] 2a ef [2] 3d e4 [2] 26 aa [2] 1b }

  condition:
    any of them
}