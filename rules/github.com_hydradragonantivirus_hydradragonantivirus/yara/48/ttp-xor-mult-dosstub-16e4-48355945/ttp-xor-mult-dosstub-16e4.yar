rule TTP_XOR_MULT_DOSStub_16e4 {
  strings:
    $key_16e4 = { 42 8c [2] 36 94 [2] 71 96 [2] 36 87 [2] 78 8b [2] 74 81 [2] 63 8a [2] 78 c4 [2] 45 }

  condition:
    any of them
}