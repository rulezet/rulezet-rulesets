rule TTP_XOR_MULT_DOSStub_463e {
  strings:
    $key_463e = { 12 56 [2] 66 4e [2] 21 4c [2] 66 5d [2] 28 51 [2] 24 5b [2] 33 50 [2] 28 1e [2] 15 }

  condition:
    any of them
}