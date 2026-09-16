rule TTP_XOR_MULT_DOSStub_4c14 {
  strings:
    $key_4c14 = { 18 7c [2] 6c 64 [2] 2b 66 [2] 6c 77 [2] 22 7b [2] 2e 71 [2] 39 7a [2] 22 34 [2] 1f }

  condition:
    any of them
}