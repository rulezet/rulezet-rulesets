rule TTP_XOR_MULT_DOSStub_777e {
  strings:
    $key_777e = { 23 16 [2] 57 0e [2] 10 0c [2] 57 1d [2] 19 11 [2] 15 1b [2] 02 10 [2] 19 5e [2] 24 }

  condition:
    any of them
}