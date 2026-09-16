rule TTP_XOR_MULT_DOSStub_9ad7 {
  strings:
    $key_9ad7 = { ce bf [2] ba a7 [2] fd a5 [2] ba b4 [2] f4 b8 [2] f8 b2 [2] ef b9 [2] f4 f7 [2] c9 }

  condition:
    any of them
}