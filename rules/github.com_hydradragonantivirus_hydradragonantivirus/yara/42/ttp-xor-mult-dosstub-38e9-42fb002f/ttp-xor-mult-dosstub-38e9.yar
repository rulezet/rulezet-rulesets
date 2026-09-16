rule TTP_XOR_MULT_DOSStub_38e9 {
  strings:
    $key_38e9 = { 6c 81 [2] 18 99 [2] 5f 9b [2] 18 8a [2] 56 86 [2] 5a 8c [2] 4d 87 [2] 56 c9 [2] 6b }

  condition:
    any of them
}