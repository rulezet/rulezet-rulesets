rule TTP_XOR_MULT_DOSStub_513e {
  strings:
    $key_513e = { 05 56 [2] 71 4e [2] 36 4c [2] 71 5d [2] 3f 51 [2] 33 5b [2] 24 50 [2] 3f 1e [2] 02 }

  condition:
    any of them
}