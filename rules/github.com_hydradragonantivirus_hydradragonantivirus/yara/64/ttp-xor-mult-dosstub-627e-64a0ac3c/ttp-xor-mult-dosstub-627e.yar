rule TTP_XOR_MULT_DOSStub_627e {
  strings:
    $key_627e = { 36 16 [2] 42 0e [2] 05 0c [2] 42 1d [2] 0c 11 [2] 00 1b [2] 17 10 [2] 0c 5e [2] 31 }

  condition:
    any of them
}