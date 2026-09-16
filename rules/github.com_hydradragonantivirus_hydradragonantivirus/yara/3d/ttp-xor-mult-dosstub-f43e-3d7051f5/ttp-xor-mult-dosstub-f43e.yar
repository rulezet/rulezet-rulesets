rule TTP_XOR_MULT_DOSStub_f43e {
  strings:
    $key_f43e = { a0 56 [2] d4 4e [2] 93 4c [2] d4 5d [2] 9a 51 [2] 96 5b [2] 81 50 [2] 9a 1e [2] a7 }

  condition:
    any of them
}