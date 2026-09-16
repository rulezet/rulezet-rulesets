rule TTP_XOR_MULT_DOSStub_740e {
  strings:
    $key_740e = { 20 66 [2] 54 7e [2] 13 7c [2] 54 6d [2] 1a 61 [2] 16 6b [2] 01 60 [2] 1a 2e [2] 27 }

  condition:
    any of them
}