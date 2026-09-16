rule TTP_XOR_MULT_DOSStub_123e {
  strings:
    $key_123e = { 46 56 [2] 32 4e [2] 75 4c [2] 32 5d [2] 7c 51 [2] 70 5b [2] 67 50 [2] 7c 1e [2] 41 }

  condition:
    any of them
}