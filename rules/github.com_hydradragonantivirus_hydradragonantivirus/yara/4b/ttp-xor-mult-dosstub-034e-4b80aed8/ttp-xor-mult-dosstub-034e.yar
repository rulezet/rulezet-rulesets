rule TTP_XOR_MULT_DOSStub_034e {
  strings:
    $key_034e = { 57 26 [2] 23 3e [2] 64 3c [2] 23 2d [2] 6d 21 [2] 61 2b [2] 76 20 [2] 6d 6e [2] 50 }

  condition:
    any of them
}