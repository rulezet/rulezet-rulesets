rule TTP_XOR_MULT_DOSStub_d98a {
  strings:
    $key_d98a = { 8d e2 [2] f9 fa [2] be f8 [2] f9 e9 [2] b7 e5 [2] bb ef [2] ac e4 [2] b7 aa [2] 8a }

  condition:
    any of them
}