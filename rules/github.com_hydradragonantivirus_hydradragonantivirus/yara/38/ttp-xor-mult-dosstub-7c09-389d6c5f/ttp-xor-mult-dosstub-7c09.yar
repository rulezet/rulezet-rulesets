rule TTP_XOR_MULT_DOSStub_7c09 {
  strings:
    $key_7c09 = { 28 61 [2] 5c 79 [2] 1b 7b [2] 5c 6a [2] 12 66 [2] 1e 6c [2] 09 67 [2] 12 29 [2] 2f }

  condition:
    any of them
}