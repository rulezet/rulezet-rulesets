rule TTP_XOR_MULT_DOSStub_7c58 {
  strings:
    $key_7c58 = { 28 30 [2] 5c 28 [2] 1b 2a [2] 5c 3b [2] 12 37 [2] 1e 3d [2] 09 36 [2] 12 78 [2] 2f }

  condition:
    any of them
}