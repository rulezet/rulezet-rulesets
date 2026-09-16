rule TTP_XOR_MULT_DOSStub_4c75 {
  strings:
    $key_4c75 = { 18 1d [2] 6c 05 [2] 2b 07 [2] 6c 16 [2] 22 1a [2] 2e 10 [2] 39 1b [2] 22 55 [2] 1f }

  condition:
    any of them
}