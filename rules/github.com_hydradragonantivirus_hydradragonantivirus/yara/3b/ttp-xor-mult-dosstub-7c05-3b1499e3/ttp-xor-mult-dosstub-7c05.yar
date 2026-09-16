rule TTP_XOR_MULT_DOSStub_7c05 {
  strings:
    $key_7c05 = { 28 6d [2] 5c 75 [2] 1b 77 [2] 5c 66 [2] 12 6a [2] 1e 60 [2] 09 6b [2] 12 25 [2] 2f }

  condition:
    any of them
}