rule TTP_XOR_MULT_DOSStub_39e4 {
  strings:
    $key_39e4 = { 6d 8c [2] 19 94 [2] 5e 96 [2] 19 87 [2] 57 8b [2] 5b 81 [2] 4c 8a [2] 57 c4 [2] 6a }

  condition:
    any of them
}