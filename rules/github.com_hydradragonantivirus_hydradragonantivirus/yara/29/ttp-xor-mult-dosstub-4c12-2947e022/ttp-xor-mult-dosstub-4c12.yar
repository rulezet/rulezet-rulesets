rule TTP_XOR_MULT_DOSStub_4c12 {
  strings:
    $key_4c12 = { 18 7a [2] 6c 62 [2] 2b 60 [2] 6c 71 [2] 22 7d [2] 2e 77 [2] 39 7c [2] 22 32 [2] 1f }

  condition:
    any of them
}