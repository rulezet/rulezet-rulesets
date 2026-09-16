rule TTP_XOR_MULT_DOSStub_f46e {
  strings:
    $key_f46e = { a0 06 [2] d4 1e [2] 93 1c [2] d4 0d [2] 9a 01 [2] 96 0b [2] 81 00 [2] 9a 4e [2] a7 }

  condition:
    any of them
}