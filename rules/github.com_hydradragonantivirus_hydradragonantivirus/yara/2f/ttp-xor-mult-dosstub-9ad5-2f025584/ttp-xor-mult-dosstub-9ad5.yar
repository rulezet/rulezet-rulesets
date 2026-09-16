rule TTP_XOR_MULT_DOSStub_9ad5 {
  strings:
    $key_9ad5 = { ce bd [2] ba a5 [2] fd a7 [2] ba b6 [2] f4 ba [2] f8 b0 [2] ef bb [2] f4 f5 [2] c9 }

  condition:
    any of them
}