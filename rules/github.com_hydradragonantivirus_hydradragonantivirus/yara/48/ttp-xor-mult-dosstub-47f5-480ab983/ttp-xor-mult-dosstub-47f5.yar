rule TTP_XOR_MULT_DOSStub_47f5 {
  strings:
    $key_47f5 = { 13 9d [2] 67 85 [2] 20 87 [2] 67 96 [2] 29 9a [2] 25 90 [2] 32 9b [2] 29 d5 [2] 14 }

  condition:
    any of them
}