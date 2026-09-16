rule TTP_XOR_MULT_DOSStub_f56e {
  strings:
    $key_f56e = { a1 06 [2] d5 1e [2] 92 1c [2] d5 0d [2] 9b 01 [2] 97 0b [2] 80 00 [2] 9b 4e [2] a6 }

  condition:
    any of them
}