rule TTP_XOR_MULT_DOSStub_7ce4 {
  strings:
    $key_7ce4 = { 28 8c [2] 5c 94 [2] 1b 96 [2] 5c 87 [2] 12 8b [2] 1e 81 [2] 09 8a [2] 12 c4 [2] 2f }

  condition:
    any of them
}