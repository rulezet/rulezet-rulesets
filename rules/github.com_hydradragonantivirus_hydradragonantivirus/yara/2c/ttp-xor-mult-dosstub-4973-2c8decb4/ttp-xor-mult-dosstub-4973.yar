rule TTP_XOR_MULT_DOSStub_4973 {
  strings:
    $key_4973 = { 1d 1b [2] 69 03 [2] 2e 01 [2] 69 10 [2] 27 1c [2] 2b 16 [2] 3c 1d [2] 27 53 [2] 1a }

  condition:
    any of them
}