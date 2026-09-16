rule TTP_XOR_MULT_DOSStub_467e {
  strings:
    $key_467e = { 12 16 [2] 66 0e [2] 21 0c [2] 66 1d [2] 28 11 [2] 24 1b [2] 33 10 [2] 28 5e [2] 15 }

  condition:
    any of them
}