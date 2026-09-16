rule TTP_XOR_MULT_DOSStub_4c04 {
  strings:
    $key_4c04 = { 18 6c [2] 6c 74 [2] 2b 76 [2] 6c 67 [2] 22 6b [2] 2e 61 [2] 39 6a [2] 22 24 [2] 1f }

  condition:
    any of them
}