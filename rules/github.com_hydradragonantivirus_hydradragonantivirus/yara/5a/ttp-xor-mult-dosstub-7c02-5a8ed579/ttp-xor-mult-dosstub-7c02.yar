rule TTP_XOR_MULT_DOSStub_7c02 {
  strings:
    $key_7c02 = { 28 6a [2] 5c 72 [2] 1b 70 [2] 5c 61 [2] 12 6d [2] 1e 67 [2] 09 6c [2] 12 22 [2] 2f }

  condition:
    any of them
}