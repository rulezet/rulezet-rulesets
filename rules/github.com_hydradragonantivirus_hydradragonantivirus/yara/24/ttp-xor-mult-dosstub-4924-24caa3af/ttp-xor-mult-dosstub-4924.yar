rule TTP_XOR_MULT_DOSStub_4924 {
  strings:
    $key_4924 = { 1d 4c [2] 69 54 [2] 2e 56 [2] 69 47 [2] 27 4b [2] 2b 41 [2] 3c 4a [2] 27 04 [2] 1a }

  condition:
    any of them
}