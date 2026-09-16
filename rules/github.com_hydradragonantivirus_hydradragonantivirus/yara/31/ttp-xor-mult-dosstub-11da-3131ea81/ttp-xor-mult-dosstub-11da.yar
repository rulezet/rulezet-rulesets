rule TTP_XOR_MULT_DOSStub_11da {
  strings:
    $key_11da = { 45 b2 [2] 31 aa [2] 76 a8 [2] 31 b9 [2] 7f b5 [2] 73 bf [2] 64 b4 [2] 7f fa [2] 42 }

  condition:
    any of them
}