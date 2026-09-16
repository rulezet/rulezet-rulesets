rule TTP_XOR_MULT_DOSStub_2bd0 {
  strings:
    $key_2bd0 = { 7f b8 [2] 0b a0 [2] 4c a2 [2] 0b b3 [2] 45 bf [2] 49 b5 [2] 5e be [2] 45 f0 [2] 78 }

  condition:
    any of them
}