rule TTP_XOR_MULT_DOSStub_4a0e {
  strings:
    $key_4a0e = { 1e 66 [2] 6a 7e [2] 2d 7c [2] 6a 6d [2] 24 61 [2] 28 6b [2] 3f 60 [2] 24 2e [2] 19 }

  condition:
    any of them
}