rule TTP_XOR_MULT_DOSStub_f07e {
  strings:
    $key_f07e = { a4 16 [2] d0 0e [2] 97 0c [2] d0 1d [2] 9e 11 [2] 92 1b [2] 85 10 [2] 9e 5e [2] a3 }

  condition:
    any of them
}