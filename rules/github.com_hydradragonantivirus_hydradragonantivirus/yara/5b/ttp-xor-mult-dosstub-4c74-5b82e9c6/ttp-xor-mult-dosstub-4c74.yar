rule TTP_XOR_MULT_DOSStub_4c74 {
  strings:
    $key_4c74 = { 18 1c [2] 6c 04 [2] 2b 06 [2] 6c 17 [2] 22 1b [2] 2e 11 [2] 39 1a [2] 22 54 [2] 1f }

  condition:
    any of them
}