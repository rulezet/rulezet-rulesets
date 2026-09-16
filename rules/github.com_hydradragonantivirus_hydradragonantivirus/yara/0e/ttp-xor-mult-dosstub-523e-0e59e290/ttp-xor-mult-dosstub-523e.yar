rule TTP_XOR_MULT_DOSStub_523e {
  strings:
    $key_523e = { 06 56 [2] 72 4e [2] 35 4c [2] 72 5d [2] 3c 51 [2] 30 5b [2] 27 50 [2] 3c 1e [2] 01 }

  condition:
    any of them
}