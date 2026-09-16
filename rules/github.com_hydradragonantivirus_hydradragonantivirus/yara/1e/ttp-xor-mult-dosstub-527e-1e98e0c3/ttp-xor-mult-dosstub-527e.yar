rule TTP_XOR_MULT_DOSStub_527e {
  strings:
    $key_527e = { 06 16 [2] 72 0e [2] 35 0c [2] 72 1d [2] 3c 11 [2] 30 1b [2] 27 10 [2] 3c 5e [2] 01 }

  condition:
    any of them
}