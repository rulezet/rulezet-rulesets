rule TTP_XOR_MULT_DOSStub_7c39 {
  strings:
    $key_7c39 = { 28 51 [2] 5c 49 [2] 1b 4b [2] 5c 5a [2] 12 56 [2] 1e 5c [2] 09 57 [2] 12 19 [2] 2f }

  condition:
    any of them
}