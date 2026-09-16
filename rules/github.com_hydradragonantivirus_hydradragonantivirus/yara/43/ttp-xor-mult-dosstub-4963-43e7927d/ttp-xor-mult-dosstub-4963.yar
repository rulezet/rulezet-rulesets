rule TTP_XOR_MULT_DOSStub_4963 {
  strings:
    $key_4963 = { 1d 0b [2] 69 13 [2] 2e 11 [2] 69 00 [2] 27 0c [2] 2b 06 [2] 3c 0d [2] 27 43 [2] 1a }

  condition:
    any of them
}