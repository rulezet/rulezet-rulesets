rule TTP_XOR_MULT_DOSStub_047e {
  strings:
    $key_047e = { 50 16 [2] 24 0e [2] 63 0c [2] 24 1d [2] 6a 11 [2] 66 1b [2] 71 10 [2] 6a 5e [2] 57 }

  condition:
    any of them
}