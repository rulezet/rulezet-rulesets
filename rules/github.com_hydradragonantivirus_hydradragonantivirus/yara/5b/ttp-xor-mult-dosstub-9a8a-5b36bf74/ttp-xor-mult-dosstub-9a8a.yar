rule TTP_XOR_MULT_DOSStub_9a8a {
  strings:
    $key_9a8a = { ce e2 [2] ba fa [2] fd f8 [2] ba e9 [2] f4 e5 [2] f8 ef [2] ef e4 [2] f4 aa [2] c9 }

  condition:
    any of them
}