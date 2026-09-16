rule TTP_XOR_MULT_DOSStub_41f5 {
  strings:
    $key_41f5 = { 15 9d [2] 61 85 [2] 26 87 [2] 61 96 [2] 2f 9a [2] 23 90 [2] 34 9b [2] 2f d5 [2] 12 }

  condition:
    any of them
}