rule TTP_XOR_MULT_DOSStub_4969 {
  strings:
    $key_4969 = { 1d 01 [2] 69 19 [2] 2e 1b [2] 69 0a [2] 27 06 [2] 2b 0c [2] 3c 07 [2] 27 49 [2] 1a }

  condition:
    any of them
}