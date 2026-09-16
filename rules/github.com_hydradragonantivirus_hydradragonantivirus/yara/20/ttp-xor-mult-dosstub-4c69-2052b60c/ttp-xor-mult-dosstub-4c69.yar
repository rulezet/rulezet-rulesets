rule TTP_XOR_MULT_DOSStub_4c69 {
  strings:
    $key_4c69 = { 18 01 [2] 6c 19 [2] 2b 1b [2] 6c 0a [2] 22 06 [2] 2e 0c [2] 39 07 [2] 22 49 [2] 1f }

  condition:
    any of them
}