rule TTP_XOR_MULT_DOSStub_21e4 {
  strings:
    $key_21e4 = { 75 8c [2] 01 94 [2] 46 96 [2] 01 87 [2] 4f 8b [2] 43 81 [2] 54 8a [2] 4f c4 [2] 72 }

  condition:
    any of them
}