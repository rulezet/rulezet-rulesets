rule TTP_XOR_MULT_DOSStub_16f5 {
  strings:
    $key_16f5 = { 42 9d [2] 36 85 [2] 71 87 [2] 36 96 [2] 78 9a [2] 74 90 [2] 63 9b [2] 78 d5 [2] 45 }

  condition:
    any of them
}