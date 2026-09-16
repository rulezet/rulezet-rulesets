rule TTP_XOR_MULT_DOSStub_707e {
  strings:
    $key_707e = { 24 16 [2] 50 0e [2] 17 0c [2] 50 1d [2] 1e 11 [2] 12 1b [2] 05 10 [2] 1e 5e [2] 23 }

  condition:
    any of them
}