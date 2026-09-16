rule TTP_XOR_MULT_DOSStub_f57e {
  strings:
    $key_f57e = { a1 16 [2] d5 0e [2] 92 0c [2] d5 1d [2] 9b 11 [2] 97 1b [2] 80 10 [2] 9b 5e [2] a6 }

  condition:
    any of them
}