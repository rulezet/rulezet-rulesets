rule TTP_XOR_MULT_DOSStub_7a0e {
  strings:
    $key_7a0e = { 2e 66 [2] 5a 7e [2] 1d 7c [2] 5a 6d [2] 14 61 [2] 18 6b [2] 0f 60 [2] 14 2e [2] 29 }

  condition:
    any of them
}