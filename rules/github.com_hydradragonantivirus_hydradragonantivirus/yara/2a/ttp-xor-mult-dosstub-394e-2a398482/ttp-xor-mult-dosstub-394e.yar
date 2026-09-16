rule TTP_XOR_MULT_DOSStub_394e {
  strings:
    $key_394e = { 6d 26 [2] 19 3e [2] 5e 3c [2] 19 2d [2] 57 21 [2] 5b 2b [2] 4c 20 [2] 57 6e [2] 6a }

  condition:
    any of them
}