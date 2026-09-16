rule TTP_XOR_MULT_DOSStub_31f5 {
  strings:
    $key_31f5 = { 65 9d [2] 11 85 [2] 56 87 [2] 11 96 [2] 5f 9a [2] 53 90 [2] 44 9b [2] 5f d5 [2] 62 }

  condition:
    any of them
}