rule TTP_XOR_MULT_DOSStub_4c34 {
  strings:
    $key_4c34 = { 18 5c [2] 6c 44 [2] 2b 46 [2] 6c 57 [2] 22 5b [2] 2e 51 [2] 39 5a [2] 22 14 [2] 1f }

  condition:
    any of them
}