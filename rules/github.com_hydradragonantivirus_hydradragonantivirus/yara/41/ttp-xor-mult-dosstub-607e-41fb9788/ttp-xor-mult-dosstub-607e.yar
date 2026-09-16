rule TTP_XOR_MULT_DOSStub_607e {
  strings:
    $key_607e = { 34 16 [2] 40 0e [2] 07 0c [2] 40 1d [2] 0e 11 [2] 02 1b [2] 15 10 [2] 0e 5e [2] 33 }

  condition:
    any of them
}