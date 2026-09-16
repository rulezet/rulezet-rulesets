rule TTP_XOR_MULT_DOSStub_f43d {
  strings:
    $key_f43d = { a0 55 [2] d4 4d [2] 93 4f [2] d4 5e [2] 9a 52 [2] 96 58 [2] 81 53 [2] 9a 1d [2] a7 }

  condition:
    any of them
}