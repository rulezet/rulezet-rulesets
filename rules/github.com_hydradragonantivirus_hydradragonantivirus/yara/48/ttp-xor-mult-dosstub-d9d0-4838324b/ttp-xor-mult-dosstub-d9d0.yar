rule TTP_XOR_MULT_DOSStub_d9d0 {
  strings:
    $key_d9d0 = { 8d b8 [2] f9 a0 [2] be a2 [2] f9 b3 [2] b7 bf [2] bb b5 [2] ac be [2] b7 f0 [2] 8a }

  condition:
    any of them
}