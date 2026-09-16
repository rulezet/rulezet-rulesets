rule TTP_XOR_MULT_DOSStub_704e {
  strings:
    $key_704e = { 24 26 [2] 50 3e [2] 17 3c [2] 50 2d [2] 1e 21 [2] 12 2b [2] 05 20 [2] 1e 6e [2] 23 }

  condition:
    any of them
}