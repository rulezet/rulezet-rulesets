rule TTP_XOR_MULT_DOSStub_643e {
  strings:
    $key_643e = { 30 56 [2] 44 4e [2] 03 4c [2] 44 5d [2] 0a 51 [2] 06 5b [2] 11 50 [2] 0a 1e [2] 37 }

  condition:
    any of them
}