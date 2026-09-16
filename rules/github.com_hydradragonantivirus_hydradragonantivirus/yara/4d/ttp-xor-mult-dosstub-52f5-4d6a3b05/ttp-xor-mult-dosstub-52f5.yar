rule TTP_XOR_MULT_DOSStub_52f5 {
  strings:
    $key_52f5 = { 06 9d [2] 72 85 [2] 35 87 [2] 72 96 [2] 3c 9a [2] 30 90 [2] 27 9b [2] 3c d5 [2] 01 }

  condition:
    any of them
}