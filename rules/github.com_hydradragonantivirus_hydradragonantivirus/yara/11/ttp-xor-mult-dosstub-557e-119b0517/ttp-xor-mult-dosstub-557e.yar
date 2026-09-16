rule TTP_XOR_MULT_DOSStub_557e {
  strings:
    $key_557e = { 01 16 [2] 75 0e [2] 32 0c [2] 75 1d [2] 3b 11 [2] 37 1b [2] 20 10 [2] 3b 5e [2] 06 }

  condition:
    any of them
}