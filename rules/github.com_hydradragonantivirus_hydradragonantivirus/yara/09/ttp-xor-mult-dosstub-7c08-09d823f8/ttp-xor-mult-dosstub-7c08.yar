rule TTP_XOR_MULT_DOSStub_7c08 {
  strings:
    $key_7c08 = { 28 60 [2] 5c 78 [2] 1b 7a [2] 5c 6b [2] 12 67 [2] 1e 6d [2] 09 66 [2] 12 28 [2] 2f }

  condition:
    any of them
}