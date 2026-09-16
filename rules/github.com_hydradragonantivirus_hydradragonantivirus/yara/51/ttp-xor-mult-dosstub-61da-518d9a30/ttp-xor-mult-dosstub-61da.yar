rule TTP_XOR_MULT_DOSStub_61da {
  strings:
    $key_61da = { 35 b2 [2] 41 aa [2] 06 a8 [2] 41 b9 [2] 0f b5 [2] 03 bf [2] 14 b4 [2] 0f fa [2] 32 }

  condition:
    any of them
}