rule TTP_XOR_MULT_DOSStub_493e {
  strings:
    $key_493e = { 1d 56 [2] 69 4e [2] 2e 4c [2] 69 5d [2] 27 51 [2] 2b 5b [2] 3c 50 [2] 27 1e [2] 1a }

  condition:
    any of them
}