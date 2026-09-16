rule TTP_XOR_MULT_DOSStub_494c {
  strings:
    $key_494c = { 1d 24 [2] 69 3c [2] 2e 3e [2] 69 2f [2] 27 23 [2] 2b 29 [2] 3c 22 [2] 27 6c [2] 1a }

  condition:
    any of them
}