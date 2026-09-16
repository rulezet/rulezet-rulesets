rule TTP_XOR_MULT_DOSStub_492e {
  strings:
    $key_492e = { 1d 46 [2] 69 5e [2] 2e 5c [2] 69 4d [2] 27 41 [2] 2b 4b [2] 3c 40 [2] 27 0e [2] 1a }

  condition:
    any of them
}