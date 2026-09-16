rule TTP_XOR_MULT_DOSStub_334e {
  strings:
    $key_334e = { 67 26 [2] 13 3e [2] 54 3c [2] 13 2d [2] 5d 21 [2] 51 2b [2] 46 20 [2] 5d 6e [2] 60 }

  condition:
    any of them
}