rule TTP_XOR_MULT_DOSStub_f54e {
  strings:
    $key_f54e = { a1 26 [2] d5 3e [2] 92 3c [2] d5 2d [2] 9b 21 [2] 97 2b [2] 80 20 [2] 9b 6e [2] a6 }

  condition:
    any of them
}