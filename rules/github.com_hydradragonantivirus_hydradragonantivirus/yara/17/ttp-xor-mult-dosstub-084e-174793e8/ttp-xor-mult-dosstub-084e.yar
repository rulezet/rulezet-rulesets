rule TTP_XOR_MULT_DOSStub_084e {
  strings:
    $key_084e = { 5c 26 [2] 28 3e [2] 6f 3c [2] 28 2d [2] 66 21 [2] 6a 2b [2] 7d 20 [2] 66 6e [2] 5b }

  condition:
    any of them
}