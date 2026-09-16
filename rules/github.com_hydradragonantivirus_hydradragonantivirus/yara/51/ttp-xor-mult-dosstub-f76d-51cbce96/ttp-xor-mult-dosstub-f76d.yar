rule TTP_XOR_MULT_DOSStub_f76d {
  strings:
    $key_f76d = { a3 05 [2] d7 1d [2] 90 1f [2] d7 0e [2] 99 02 [2] 95 08 [2] 82 03 [2] 99 4d [2] a4 }

  condition:
    any of them
}