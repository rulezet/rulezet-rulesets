rule TTP_XOR_MULT_DOSStub_441e {
  strings:
    $key_441e = { 10 76 [2] 64 6e [2] 23 6c [2] 64 7d [2] 2a 71 [2] 26 7b [2] 31 70 [2] 2a 3e [2] 17 }

  condition:
    any of them
}