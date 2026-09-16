rule TTP_XOR_MULT_DOSStub_043e {
  strings:
    $key_043e = { 50 56 [2] 24 4e [2] 63 4c [2] 24 5d [2] 6a 51 [2] 66 5b [2] 71 50 [2] 6a 1e [2] 57 }

  condition:
    any of them
}