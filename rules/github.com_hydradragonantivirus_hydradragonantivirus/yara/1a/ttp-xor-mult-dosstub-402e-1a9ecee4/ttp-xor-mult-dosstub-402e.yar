rule TTP_XOR_MULT_DOSStub_402e {
  strings:
    $key_402e = { 14 46 [2] 60 5e [2] 27 5c [2] 60 4d [2] 2e 41 [2] 22 4b [2] 35 40 [2] 2e 0e [2] 13 }

  condition:
    any of them
}