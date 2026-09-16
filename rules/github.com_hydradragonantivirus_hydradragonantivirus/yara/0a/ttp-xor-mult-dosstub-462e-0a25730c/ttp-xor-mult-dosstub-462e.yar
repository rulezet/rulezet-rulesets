rule TTP_XOR_MULT_DOSStub_462e {
  strings:
    $key_462e = { 12 46 [2] 66 5e [2] 21 5c [2] 66 4d [2] 28 41 [2] 24 4b [2] 33 40 [2] 28 0e [2] 15 }

  condition:
    any of them
}