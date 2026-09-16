rule TTP_XOR_MULT_DOSStub_7ce9 {
  strings:
    $key_7ce9 = { 28 81 [2] 5c 99 [2] 1b 9b [2] 5c 8a [2] 12 86 [2] 1e 8c [2] 09 87 [2] 12 c9 [2] 2f }

  condition:
    any of them
}