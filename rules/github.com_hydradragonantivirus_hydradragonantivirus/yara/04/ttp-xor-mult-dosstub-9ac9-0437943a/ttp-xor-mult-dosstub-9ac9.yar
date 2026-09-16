rule TTP_XOR_MULT_DOSStub_9ac9 {
  strings:
    $key_9ac9 = { ce a1 [2] ba b9 [2] fd bb [2] ba aa [2] f4 a6 [2] f8 ac [2] ef a7 [2] f4 e9 [2] c9 }

  condition:
    any of them
}