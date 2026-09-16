rule TTP_XOR_MULT_DOSStub_4979 {
  strings:
    $key_4979 = { 1d 11 [2] 69 09 [2] 2e 0b [2] 69 1a [2] 27 16 [2] 2b 1c [2] 3c 17 [2] 27 59 [2] 1a }

  condition:
    any of them
}