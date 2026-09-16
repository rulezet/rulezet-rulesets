rule TTP_XOR_MULT_DOSStub_3a2e {
  strings:
    $key_3a2e = { 6e 46 [2] 1a 5e [2] 5d 5c [2] 1a 4d [2] 54 41 [2] 58 4b [2] 4f 40 [2] 54 0e [2] 69 }

  condition:
    any of them
}