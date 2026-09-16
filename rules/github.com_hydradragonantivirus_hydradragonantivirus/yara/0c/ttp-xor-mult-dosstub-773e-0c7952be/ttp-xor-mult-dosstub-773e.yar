rule TTP_XOR_MULT_DOSStub_773e {
  strings:
    $key_773e = { 23 56 [2] 57 4e [2] 10 4c [2] 57 5d [2] 19 51 [2] 15 5b [2] 02 50 [2] 19 1e [2] 24 }

  condition:
    any of them
}