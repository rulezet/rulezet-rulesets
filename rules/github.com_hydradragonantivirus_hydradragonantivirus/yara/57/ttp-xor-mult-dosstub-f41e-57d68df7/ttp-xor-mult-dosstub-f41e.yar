rule TTP_XOR_MULT_DOSStub_f41e {
  strings:
    $key_f41e = { a0 76 [2] d4 6e [2] 93 6c [2] d4 7d [2] 9a 71 [2] 96 7b [2] 81 70 [2] 9a 3e [2] a7 }

  condition:
    any of them
}