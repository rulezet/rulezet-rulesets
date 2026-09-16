rule TTP_XOR_MULT_DOSStub_701e {
  strings:
    $key_701e = { 24 76 [2] 50 6e [2] 17 6c [2] 50 7d [2] 1e 71 [2] 12 7b [2] 05 70 [2] 1e 3e [2] 23 }

  condition:
    any of them
}