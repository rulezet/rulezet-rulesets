rule TTP_XOR_MULT_DOSStub_754e {
  strings:
    $key_754e = { 21 26 [2] 55 3e [2] 12 3c [2] 55 2d [2] 1b 21 [2] 17 2b [2] 00 20 [2] 1b 6e [2] 26 }

  condition:
    any of them
}