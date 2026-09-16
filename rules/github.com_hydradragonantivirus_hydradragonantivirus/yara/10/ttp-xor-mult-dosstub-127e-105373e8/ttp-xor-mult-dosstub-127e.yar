rule TTP_XOR_MULT_DOSStub_127e {
  strings:
    $key_127e = { 46 16 [2] 32 0e [2] 75 0c [2] 32 1d [2] 7c 11 [2] 70 1b [2] 67 10 [2] 7c 5e [2] 41 }

  condition:
    any of them
}