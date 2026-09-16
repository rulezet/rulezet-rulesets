rule TTP_XOR_MULT_DOSStub_72f5 {
  strings:
    $key_72f5 = { 26 9d [2] 52 85 [2] 15 87 [2] 52 96 [2] 1c 9a [2] 10 90 [2] 07 9b [2] 1c d5 [2] 21 }

  condition:
    any of them
}