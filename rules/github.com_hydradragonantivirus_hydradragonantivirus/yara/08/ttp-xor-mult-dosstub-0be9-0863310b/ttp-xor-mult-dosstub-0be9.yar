rule TTP_XOR_MULT_DOSStub_0be9 {
  strings:
    $key_0be9 = { 5f 81 [2] 2b 99 [2] 6c 9b [2] 2b 8a [2] 65 86 [2] 69 8c [2] 7e 87 [2] 65 c9 [2] 58 }

  condition:
    any of them
}