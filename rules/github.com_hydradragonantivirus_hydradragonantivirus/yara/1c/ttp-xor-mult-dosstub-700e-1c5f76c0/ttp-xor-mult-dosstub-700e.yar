rule TTP_XOR_MULT_DOSStub_700e {
  strings:
    $key_700e = { 24 66 [2] 50 7e [2] 17 7c [2] 50 6d [2] 1e 61 [2] 12 6b [2] 05 60 [2] 1e 2e [2] 23 }

  condition:
    any of them
}