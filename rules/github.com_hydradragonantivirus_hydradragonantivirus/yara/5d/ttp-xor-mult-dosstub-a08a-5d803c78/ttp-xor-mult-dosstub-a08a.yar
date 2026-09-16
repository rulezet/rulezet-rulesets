rule TTP_XOR_MULT_DOSStub_a08a {
  strings:
    $key_a08a = { f4 e2 [2] 80 fa [2] c7 f8 [2] 80 e9 [2] ce e5 [2] c2 ef [2] d5 e4 [2] ce aa [2] f3 }

  condition:
    any of them
}