rule TTP_XOR_MULT_DOSStub_698a {
  strings:
    $key_698a = { 3d e2 [2] 49 fa [2] 0e f8 [2] 49 e9 [2] 07 e5 [2] 0b ef [2] 1c e4 [2] 07 aa [2] 3a }

  condition:
    any of them
}