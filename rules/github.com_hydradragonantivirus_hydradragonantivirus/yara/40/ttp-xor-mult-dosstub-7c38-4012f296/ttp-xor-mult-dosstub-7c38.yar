rule TTP_XOR_MULT_DOSStub_7c38 {
  strings:
    $key_7c38 = { 28 50 [2] 5c 48 [2] 1b 4a [2] 5c 5b [2] 12 57 [2] 1e 5d [2] 09 56 [2] 12 18 [2] 2f }

  condition:
    any of them
}