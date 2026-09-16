rule TTP_XOR_MULT_DOSStub_f74d {
  strings:
    $key_f74d = { a3 25 [2] d7 3d [2] 90 3f [2] d7 2e [2] 99 22 [2] 95 28 [2] 82 23 [2] 99 6d [2] a4 }

  condition:
    any of them
}