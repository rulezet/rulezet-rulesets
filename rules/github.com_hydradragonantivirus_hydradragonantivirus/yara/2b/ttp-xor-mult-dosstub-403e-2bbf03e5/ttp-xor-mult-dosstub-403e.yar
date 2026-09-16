rule TTP_XOR_MULT_DOSStub_403e {
  strings:
    $key_403e = { 14 56 [2] 60 4e [2] 27 4c [2] 60 5d [2] 2e 51 [2] 22 5b [2] 35 50 [2] 2e 1e [2] 13 }

  condition:
    any of them
}