rule TTP_XOR_MULT_DOSStub_5fd4 {
  strings:
    $key_5fd4 = { 0b bc [2] 7f a4 [2] 38 a6 [2] 7f b7 [2] 31 bb [2] 3d b1 [2] 2a ba [2] 31 f4 [2] 0c }

  condition:
    any of them
}