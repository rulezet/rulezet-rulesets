rule TTP_XOR_MULT_DOSStub_28e4 {
  strings:
    $key_28e4 = { 7c 8c [2] 08 94 [2] 4f 96 [2] 08 87 [2] 46 8b [2] 4a 81 [2] 5d 8a [2] 46 c4 [2] 7b }

  condition:
    any of them
}