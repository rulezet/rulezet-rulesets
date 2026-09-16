rule TTP_XOR_MULT_DOSStub_4c19 {
  strings:
    $key_4c19 = { 18 71 [2] 6c 69 [2] 2b 6b [2] 6c 7a [2] 22 76 [2] 2e 7c [2] 39 77 [2] 22 39 [2] 1f }

  condition:
    any of them
}