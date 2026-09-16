rule TTP_XOR_MULT_DOSStub_9ac5 {
  strings:
    $key_9ac5 = { ce ad [2] ba b5 [2] fd b7 [2] ba a6 [2] f4 aa [2] f8 a0 [2] ef ab [2] f4 e5 [2] c9 }

  condition:
    any of them
}