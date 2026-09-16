rule TTP_XOR_MULT_DOSStub_50e4 {
  strings:
    $key_50e4 = { 04 8c [2] 70 94 [2] 37 96 [2] 70 87 [2] 3e 8b [2] 32 81 [2] 25 8a [2] 3e c4 [2] 03 }

  condition:
    any of them
}