rule TTP_XOR_MULT_DOSStub_f46d {
  strings:
    $key_f46d = { a0 05 [2] d4 1d [2] 93 1f [2] d4 0e [2] 9a 02 [2] 96 08 [2] 81 03 [2] 9a 4d [2] a7 }

  condition:
    any of them
}