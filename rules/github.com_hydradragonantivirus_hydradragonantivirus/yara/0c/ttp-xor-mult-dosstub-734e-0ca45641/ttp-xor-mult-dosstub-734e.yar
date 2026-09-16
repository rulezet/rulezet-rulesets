rule TTP_XOR_MULT_DOSStub_734e {
  strings:
    $key_734e = { 27 26 [2] 53 3e [2] 14 3c [2] 53 2d [2] 1d 21 [2] 11 2b [2] 06 20 [2] 1d 6e [2] 20 }

  condition:
    any of them
}