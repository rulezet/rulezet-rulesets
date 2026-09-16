rule TTP_XOR_MULT_DOSStub_413e {
  strings:
    $key_413e = { 15 56 [2] 61 4e [2] 26 4c [2] 61 5d [2] 2f 51 [2] 23 5b [2] 34 50 [2] 2f 1e [2] 12 }

  condition:
    any of them
}