rule TTP_XOR_MULT_DOSStub_1a3e {
  strings:
    $key_1a3e = { 4e 56 [2] 3a 4e [2] 7d 4c [2] 3a 5d [2] 74 51 [2] 78 5b [2] 6f 50 [2] 74 1e [2] 49 }

  condition:
    any of them
}