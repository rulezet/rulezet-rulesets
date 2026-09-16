rule TTP_XOR_MULT_DOSStub_491e {
  strings:
    $key_491e = { 1d 76 [2] 69 6e [2] 2e 6c [2] 69 7d [2] 27 71 [2] 2b 7b [2] 3c 70 [2] 27 3e [2] 1a }

  condition:
    any of them
}