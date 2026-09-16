rule TTP_XOR_MULT_DOSStub_440e {
  strings:
    $key_440e = { 10 66 [2] 64 7e [2] 23 7c [2] 64 6d [2] 2a 61 [2] 26 6b [2] 31 60 [2] 2a 2e [2] 17 }

  condition:
    any of them
}