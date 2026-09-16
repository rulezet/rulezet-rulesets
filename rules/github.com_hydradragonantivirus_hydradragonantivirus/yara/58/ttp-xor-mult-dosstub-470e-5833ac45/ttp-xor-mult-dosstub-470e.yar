rule TTP_XOR_MULT_DOSStub_470e {
  strings:
    $key_470e = { 13 66 [2] 67 7e [2] 20 7c [2] 67 6d [2] 29 61 [2] 25 6b [2] 32 60 [2] 29 2e [2] 14 }

  condition:
    any of them
}