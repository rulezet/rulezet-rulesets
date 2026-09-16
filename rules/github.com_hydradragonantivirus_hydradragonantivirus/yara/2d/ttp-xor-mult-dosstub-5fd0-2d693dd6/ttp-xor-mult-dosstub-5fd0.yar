rule TTP_XOR_MULT_DOSStub_5fd0 {
  strings:
    $key_5fd0 = { 0b b8 [2] 7f a0 [2] 38 a2 [2] 7f b3 [2] 31 bf [2] 3d b5 [2] 2a be [2] 31 f0 [2] 0c }

  condition:
    any of them
}