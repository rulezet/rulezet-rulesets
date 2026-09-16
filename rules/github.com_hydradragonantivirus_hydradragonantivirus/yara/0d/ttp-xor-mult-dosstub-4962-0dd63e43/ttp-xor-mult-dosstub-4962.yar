rule TTP_XOR_MULT_DOSStub_4962 {
  strings:
    $key_4962 = { 1d 0a [2] 69 12 [2] 2e 10 [2] 69 01 [2] 27 0d [2] 2b 07 [2] 3c 0c [2] 27 42 [2] 1a }

  condition:
    any of them
}