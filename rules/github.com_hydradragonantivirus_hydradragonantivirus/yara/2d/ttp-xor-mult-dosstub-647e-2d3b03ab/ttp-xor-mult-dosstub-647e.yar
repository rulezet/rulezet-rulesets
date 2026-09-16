rule TTP_XOR_MULT_DOSStub_647e {
  strings:
    $key_647e = { 30 16 [2] 44 0e [2] 03 0c [2] 44 1d [2] 0a 11 [2] 06 1b [2] 11 10 [2] 0a 5e [2] 37 }

  condition:
    any of them
}