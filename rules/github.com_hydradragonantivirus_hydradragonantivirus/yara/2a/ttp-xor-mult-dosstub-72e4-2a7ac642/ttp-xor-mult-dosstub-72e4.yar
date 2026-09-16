rule TTP_XOR_MULT_DOSStub_72e4 {
  strings:
    $key_72e4 = { 26 8c [2] 52 94 [2] 15 96 [2] 52 87 [2] 1c 8b [2] 10 81 [2] 07 8a [2] 1c c4 [2] 21 }

  condition:
    any of them
}