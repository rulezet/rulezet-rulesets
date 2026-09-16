rule TTP_XOR_MULT_DOSStub_7c04 {
  strings:
    $key_7c04 = { 28 6c [2] 5c 74 [2] 1b 76 [2] 5c 67 [2] 12 6b [2] 1e 61 [2] 09 6a [2] 12 24 [2] 2f }

  condition:
    any of them
}