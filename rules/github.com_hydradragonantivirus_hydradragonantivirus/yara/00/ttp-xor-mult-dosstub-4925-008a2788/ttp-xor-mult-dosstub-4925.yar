rule TTP_XOR_MULT_DOSStub_4925 {
  strings:
    $key_4925 = { 1d 4d [2] 69 55 [2] 2e 57 [2] 69 46 [2] 27 4a [2] 2b 40 [2] 3c 4b [2] 27 05 [2] 1a }

  condition:
    any of them
}