rule TTP_XOR_MULT_DOSStub_4c38 {
  strings:
    $key_4c38 = { 18 50 [2] 6c 48 [2] 2b 4a [2] 6c 5b [2] 22 57 [2] 2e 5d [2] 39 56 [2] 22 18 [2] 1f }

  condition:
    any of them
}