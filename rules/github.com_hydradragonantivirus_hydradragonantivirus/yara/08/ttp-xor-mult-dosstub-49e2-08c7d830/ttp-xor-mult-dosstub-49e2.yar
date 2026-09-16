rule TTP_XOR_MULT_DOSStub_49e2 {
  strings:
    $key_49e2 = { 1d 8a [2] 69 92 [2] 2e 90 [2] 69 81 [2] 27 8d [2] 2b 87 [2] 3c 8c [2] 27 c2 [2] 1a }

  condition:
    any of them
}