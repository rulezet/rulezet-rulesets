rule TTP_XOR_MULT_DOSStub_623e {
  strings:
    $key_623e = { 36 56 [2] 42 4e [2] 05 4c [2] 42 5d [2] 0c 51 [2] 00 5b [2] 17 50 [2] 0c 1e [2] 31 }

  condition:
    any of them
}