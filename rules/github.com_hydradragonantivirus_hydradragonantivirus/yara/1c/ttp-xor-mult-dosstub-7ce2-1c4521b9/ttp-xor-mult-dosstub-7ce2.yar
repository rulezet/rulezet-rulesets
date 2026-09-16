rule TTP_XOR_MULT_DOSStub_7ce2 {
  strings:
    $key_7ce2 = { 28 8a [2] 5c 92 [2] 1b 90 [2] 5c 81 [2] 12 8d [2] 1e 87 [2] 09 8c [2] 12 c2 [2] 2f }

  condition:
    any of them
}