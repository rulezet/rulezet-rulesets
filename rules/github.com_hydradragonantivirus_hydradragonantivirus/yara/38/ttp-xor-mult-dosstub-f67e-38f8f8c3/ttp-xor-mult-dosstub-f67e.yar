rule TTP_XOR_MULT_DOSStub_f67e {
  strings:
    $key_f67e = { a2 16 [2] d6 0e [2] 91 0c [2] d6 1d [2] 98 11 [2] 94 1b [2] 83 10 [2] 98 5e [2] a5 }

  condition:
    any of them
}