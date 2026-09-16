rule TTP_XOR_MULT_DOSStub_042e {
  strings:
    $key_042e = { 50 46 [2] 24 5e [2] 63 5c [2] 24 4d [2] 6a 41 [2] 66 4b [2] 71 40 [2] 6a 0e [2] 57 }

  condition:
    any of them
}