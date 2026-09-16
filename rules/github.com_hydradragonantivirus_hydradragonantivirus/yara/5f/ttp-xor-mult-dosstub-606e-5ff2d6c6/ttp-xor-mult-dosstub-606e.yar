rule TTP_XOR_MULT_DOSStub_606e {
  strings:
    $key_606e = { 34 06 [2] 40 1e [2] 07 1c [2] 40 0d [2] 0e 01 [2] 02 0b [2] 15 00 [2] 0e 4e [2] 33 }

  condition:
    any of them
}