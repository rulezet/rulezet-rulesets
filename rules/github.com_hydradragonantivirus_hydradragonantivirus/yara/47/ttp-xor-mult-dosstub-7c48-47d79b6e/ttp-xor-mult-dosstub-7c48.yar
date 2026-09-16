rule TTP_XOR_MULT_DOSStub_7c48 {
  strings:
    $key_7c48 = { 28 20 [2] 5c 38 [2] 1b 3a [2] 5c 2b [2] 12 27 [2] 1e 2d [2] 09 26 [2] 12 68 [2] 2f }

  condition:
    any of them
}