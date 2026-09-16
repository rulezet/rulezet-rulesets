rule TTP_XOR_MULT_DOSStub_4c02 {
  strings:
    $key_4c02 = { 18 6a [2] 6c 72 [2] 2b 70 [2] 6c 61 [2] 22 6d [2] 2e 67 [2] 39 6c [2] 22 22 [2] 1f }

  condition:
    any of them
}