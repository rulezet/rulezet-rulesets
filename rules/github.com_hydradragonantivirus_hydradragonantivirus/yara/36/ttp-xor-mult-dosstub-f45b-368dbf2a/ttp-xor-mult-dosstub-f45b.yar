rule TTP_XOR_MULT_DOSStub_f45b {
  strings:
    $key_f45b = { a0 33 [2] d4 2b [2] 93 29 [2] d4 38 [2] 9a 34 [2] 96 3e [2] 81 35 [2] 9a 7b [2] a7 }

  condition:
    any of them
}