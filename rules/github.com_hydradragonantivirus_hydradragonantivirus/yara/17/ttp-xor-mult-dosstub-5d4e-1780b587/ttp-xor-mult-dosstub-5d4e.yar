rule TTP_XOR_MULT_DOSStub_5d4e {
  strings:
    $key_5d4e = { 09 26 [2] 7d 3e [2] 3a 3c [2] 7d 2d [2] 33 21 [2] 3f 2b [2] 28 20 [2] 33 6e [2] 0e }

  condition:
    any of them
}