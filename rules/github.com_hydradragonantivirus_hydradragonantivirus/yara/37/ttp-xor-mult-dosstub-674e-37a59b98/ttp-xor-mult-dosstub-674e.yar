rule TTP_XOR_MULT_DOSStub_674e {
  strings:
    $key_674e = { 33 26 [2] 47 3e [2] 00 3c [2] 47 2d [2] 09 21 [2] 05 2b [2] 12 20 [2] 09 6e [2] 34 }

  condition:
    any of them
}