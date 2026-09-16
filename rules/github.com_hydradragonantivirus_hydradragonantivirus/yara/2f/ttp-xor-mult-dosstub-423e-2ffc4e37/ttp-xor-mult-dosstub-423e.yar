rule TTP_XOR_MULT_DOSStub_423e {
  strings:
    $key_423e = { 16 56 [2] 62 4e [2] 25 4c [2] 62 5d [2] 2c 51 [2] 20 5b [2] 37 50 [2] 2c 1e [2] 11 }

  condition:
    any of them
}