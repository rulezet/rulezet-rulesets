rule TTP_XOR_MULT_DOSStub_9ac3 {
  strings:
    $key_9ac3 = { ce ab [2] ba b3 [2] fd b1 [2] ba a0 [2] f4 ac [2] f8 a6 [2] ef ad [2] f4 e3 [2] c9 }

  condition:
    any of them
}