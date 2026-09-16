rule TTP_XOR_MULT_DOSStub_3a0e {
  strings:
    $key_3a0e = { 6e 66 [2] 1a 7e [2] 5d 7c [2] 1a 6d [2] 54 61 [2] 58 6b [2] 4f 60 [2] 54 2e [2] 69 }

  condition:
    any of them
}