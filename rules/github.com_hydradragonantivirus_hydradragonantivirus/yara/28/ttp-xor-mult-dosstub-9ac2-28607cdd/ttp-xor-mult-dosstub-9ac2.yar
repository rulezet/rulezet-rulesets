rule TTP_XOR_MULT_DOSStub_9ac2 {
  strings:
    $key_9ac2 = { ce aa [2] ba b2 [2] fd b0 [2] ba a1 [2] f4 ad [2] f8 a7 [2] ef ac [2] f4 e2 [2] c9 }

  condition:
    any of them
}