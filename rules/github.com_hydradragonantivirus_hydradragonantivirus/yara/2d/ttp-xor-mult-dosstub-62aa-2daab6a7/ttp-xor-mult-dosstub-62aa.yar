rule TTP_XOR_MULT_DOSStub_62aa {
  strings:
    $key_62aa = { 36 c2 [2] 42 da [2] 05 d8 [2] 42 c9 [2] 0c c5 [2] 00 cf [2] 17 c4 [2] 0c 8a [2] 31 }

  condition:
    any of them
}