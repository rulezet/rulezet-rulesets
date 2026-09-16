rule TTP_XOR_MULT_DOSStub_d9d1 {
  strings:
    $key_d9d1 = { 8d b9 [2] f9 a1 [2] be a3 [2] f9 b2 [2] b7 be [2] bb b4 [2] ac bf [2] b7 f1 [2] 8a }

  condition:
    any of them
}