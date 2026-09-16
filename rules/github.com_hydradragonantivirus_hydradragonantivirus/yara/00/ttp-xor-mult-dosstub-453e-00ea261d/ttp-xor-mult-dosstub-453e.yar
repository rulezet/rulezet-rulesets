rule TTP_XOR_MULT_DOSStub_453e {
  strings:
    $key_453e = { 11 56 [2] 65 4e [2] 22 4c [2] 65 5d [2] 2b 51 [2] 27 5b [2] 30 50 [2] 2b 1e [2] 16 }

  condition:
    any of them
}