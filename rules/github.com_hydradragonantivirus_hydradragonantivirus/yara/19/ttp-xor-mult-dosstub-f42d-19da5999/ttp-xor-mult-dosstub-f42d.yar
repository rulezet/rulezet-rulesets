rule TTP_XOR_MULT_DOSStub_f42d {
  strings:
    $key_f42d = { a0 45 [2] d4 5d [2] 93 5f [2] d4 4e [2] 9a 42 [2] 96 48 [2] 81 43 [2] 9a 0d [2] a7 }

  condition:
    any of them
}