rule TTP_XOR_MULT_DOSStub_7de9 {
  strings:
    $key_7de9 = { 29 81 [2] 5d 99 [2] 1a 9b [2] 5d 8a [2] 13 86 [2] 1f 8c [2] 08 87 [2] 13 c9 [2] 2e }

  condition:
    any of them
}