rule TTP_XOR_MULT_DOSStub_f26d {
  strings:
    $key_f26d = { a6 05 [2] d2 1d [2] 95 1f [2] d2 0e [2] 9c 02 [2] 90 08 [2] 87 03 [2] 9c 4d [2] a1 }

  condition:
    any of them
}