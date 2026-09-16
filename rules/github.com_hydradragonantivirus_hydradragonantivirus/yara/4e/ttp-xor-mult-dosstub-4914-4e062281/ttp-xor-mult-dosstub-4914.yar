rule TTP_XOR_MULT_DOSStub_4914 {
  strings:
    $key_4914 = { 1d 7c [2] 69 64 [2] 2e 66 [2] 69 77 [2] 27 7b [2] 2b 71 [2] 3c 7a [2] 27 34 [2] 1a }

  condition:
    any of them
}