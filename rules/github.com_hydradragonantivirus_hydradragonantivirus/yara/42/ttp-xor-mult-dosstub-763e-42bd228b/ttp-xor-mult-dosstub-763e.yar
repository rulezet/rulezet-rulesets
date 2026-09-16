rule TTP_XOR_MULT_DOSStub_763e {
  strings:
    $key_763e = { 22 56 [2] 56 4e [2] 11 4c [2] 56 5d [2] 18 51 [2] 14 5b [2] 03 50 [2] 18 1e [2] 25 }

  condition:
    any of them
}