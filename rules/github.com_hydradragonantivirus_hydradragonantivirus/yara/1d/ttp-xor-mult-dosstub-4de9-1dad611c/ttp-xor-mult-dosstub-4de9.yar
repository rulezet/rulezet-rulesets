rule TTP_XOR_MULT_DOSStub_4de9 {
  strings:
    $key_4de9 = { 19 81 [2] 6d 99 [2] 2a 9b [2] 6d 8a [2] 23 86 [2] 2f 8c [2] 38 87 [2] 23 c9 [2] 1e }

  condition:
    any of them
}