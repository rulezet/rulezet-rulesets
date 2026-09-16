rule TTP_XOR_MULT_DOSStub_38e4 {
  strings:
    $key_38e4 = { 6c 8c [2] 18 94 [2] 5f 96 [2] 18 87 [2] 56 8b [2] 5a 81 [2] 4d 8a [2] 56 c4 [2] 6b }

  condition:
    any of them
}