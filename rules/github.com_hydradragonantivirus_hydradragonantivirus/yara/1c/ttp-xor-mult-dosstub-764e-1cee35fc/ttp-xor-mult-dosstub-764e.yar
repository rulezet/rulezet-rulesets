rule TTP_XOR_MULT_DOSStub_764e {
  strings:
    $key_764e = { 22 26 [2] 56 3e [2] 11 3c [2] 56 2d [2] 18 21 [2] 14 2b [2] 03 20 [2] 18 6e [2] 25 }

  condition:
    any of them
}