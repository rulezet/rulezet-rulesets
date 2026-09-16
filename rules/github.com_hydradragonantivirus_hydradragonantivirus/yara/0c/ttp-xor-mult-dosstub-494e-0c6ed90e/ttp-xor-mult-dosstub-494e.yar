rule TTP_XOR_MULT_DOSStub_494e {
  strings:
    $key_494e = { 1d 26 [2] 69 3e [2] 2e 3c [2] 69 2d [2] 27 21 [2] 2b 2b [2] 3c 20 [2] 27 6e [2] 1a }

  condition:
    any of them
}