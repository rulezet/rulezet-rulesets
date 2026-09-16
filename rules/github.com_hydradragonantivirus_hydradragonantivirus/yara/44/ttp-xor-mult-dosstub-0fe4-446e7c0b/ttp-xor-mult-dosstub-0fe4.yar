rule TTP_XOR_MULT_DOSStub_0fe4 {
  strings:
    $key_0fe4 = { 5b 8c [2] 2f 94 [2] 68 96 [2] 2f 87 [2] 61 8b [2] 6d 81 [2] 7a 8a [2] 61 c4 [2] 5c }

  condition:
    any of them
}