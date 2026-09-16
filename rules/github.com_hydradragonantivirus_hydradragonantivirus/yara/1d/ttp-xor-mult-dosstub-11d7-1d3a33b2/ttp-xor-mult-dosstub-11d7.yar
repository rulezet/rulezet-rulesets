rule TTP_XOR_MULT_DOSStub_11d7 {
  strings:
    $key_11d7 = { 45 bf [2] 31 a7 [2] 76 a5 [2] 31 b4 [2] 7f b8 [2] 73 b2 [2] 64 b9 [2] 7f f7 [2] 42 }

  condition:
    any of them
}