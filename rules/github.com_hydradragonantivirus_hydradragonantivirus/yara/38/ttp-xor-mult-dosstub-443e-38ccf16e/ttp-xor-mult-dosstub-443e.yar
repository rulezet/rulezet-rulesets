rule TTP_XOR_MULT_DOSStub_443e {
  strings:
    $key_443e = { 10 56 [2] 64 4e [2] 23 4c [2] 64 5d [2] 2a 51 [2] 26 5b [2] 31 50 [2] 2a 1e [2] 17 }

  condition:
    any of them
}