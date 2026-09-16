rule TTP_XOR_MULT_DOSStub_414e {
  strings:
    $key_414e = { 15 26 [2] 61 3e [2] 26 3c [2] 61 2d [2] 2f 21 [2] 23 2b [2] 34 20 [2] 2f 6e [2] 12 }

  condition:
    any of them
}