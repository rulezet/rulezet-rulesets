rule TTP_XOR_MULT_DOSStub_3a1e {
  strings:
    $key_3a1e = { 6e 76 [2] 1a 6e [2] 5d 6c [2] 1a 7d [2] 54 71 [2] 58 7b [2] 4f 70 [2] 54 3e [2] 69 }

  condition:
    any of them
}