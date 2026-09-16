rule TTP_XOR_MULT_DOSStub_f45d {
  strings:
    $key_f45d = { a0 35 [2] d4 2d [2] 93 2f [2] d4 3e [2] 9a 32 [2] 96 38 [2] 81 33 [2] 9a 7d [2] a7 }

  condition:
    any of them
}