rule TTP_XOR_MULT_DOSStub_490e {
  strings:
    $key_490e = { 1d 66 [2] 69 7e [2] 2e 7c [2] 69 6d [2] 27 61 [2] 2b 6b [2] 3c 60 [2] 27 2e [2] 1a }

  condition:
    any of them
}