rule TTP_XOR_MULT_DOSStub_732e {
  strings:
    $key_732e = { 27 46 [2] 53 5e [2] 14 5c [2] 53 4d [2] 1d 41 [2] 11 4b [2] 06 40 [2] 1d 0e [2] 20 }

  condition:
    any of them
}