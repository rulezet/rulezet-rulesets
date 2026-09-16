rule TTP_XOR_MULT_DOSStub_644e {
  strings:
    $key_644e = { 30 26 [2] 44 3e [2] 03 3c [2] 44 2d [2] 0a 21 [2] 06 2b [2] 11 20 [2] 0a 6e [2] 37 }

  condition:
    any of them
}