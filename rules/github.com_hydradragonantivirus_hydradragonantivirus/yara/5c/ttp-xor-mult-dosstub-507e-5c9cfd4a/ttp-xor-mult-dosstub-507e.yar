rule TTP_XOR_MULT_DOSStub_507e {
  strings:
    $key_507e = { 04 16 [2] 70 0e [2] 37 0c [2] 70 1d [2] 3e 11 [2] 32 1b [2] 25 10 [2] 3e 5e [2] 03 }

  condition:
    any of them
}