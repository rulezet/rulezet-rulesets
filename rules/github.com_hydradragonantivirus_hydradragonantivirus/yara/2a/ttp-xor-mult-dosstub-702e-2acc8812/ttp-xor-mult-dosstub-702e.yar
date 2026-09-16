rule TTP_XOR_MULT_DOSStub_702e {
  strings:
    $key_702e = { 24 46 [2] 50 5e [2] 17 5c [2] 50 4d [2] 1e 41 [2] 12 4b [2] 05 40 [2] 1e 0e [2] 23 }

  condition:
    any of them
}