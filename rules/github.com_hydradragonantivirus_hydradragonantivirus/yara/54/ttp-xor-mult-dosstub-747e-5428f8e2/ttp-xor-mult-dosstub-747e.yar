rule TTP_XOR_MULT_DOSStub_747e {
  strings:
    $key_747e = { 20 16 [2] 54 0e [2] 13 0c [2] 54 1d [2] 1a 11 [2] 16 1b [2] 01 10 [2] 1a 5e [2] 27 }

  condition:
    any of them
}