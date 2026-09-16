rule TTP_XOR_MULT_DOSStub_030e {
  strings:
    $key_030e = { 57 66 [2] 23 7e [2] 64 7c [2] 23 6d [2] 6d 61 [2] 61 6b [2] 76 60 [2] 6d 2e [2] 50 }

  condition:
    any of them
}