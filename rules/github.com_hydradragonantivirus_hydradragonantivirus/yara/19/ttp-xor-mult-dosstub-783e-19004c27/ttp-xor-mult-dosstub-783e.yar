rule TTP_XOR_MULT_DOSStub_783e {
  strings:
    $key_783e = { 2c 56 [2] 58 4e [2] 1f 4c [2] 58 5d [2] 16 51 [2] 1a 5b [2] 0d 50 [2] 16 1e [2] 2b }

  condition:
    any of them
}