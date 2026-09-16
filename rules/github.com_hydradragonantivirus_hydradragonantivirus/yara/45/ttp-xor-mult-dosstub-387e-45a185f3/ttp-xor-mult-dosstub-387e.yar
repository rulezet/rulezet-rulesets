rule TTP_XOR_MULT_DOSStub_387e {
  strings:
    $key_387e = { 6c 16 [2] 18 0e [2] 5f 0c [2] 18 1d [2] 56 11 [2] 5a 1b [2] 4d 10 [2] 56 5e [2] 6b }

  condition:
    any of them
}