rule TTP_XOR_MULT_DOSStub_466d {
  strings:
    $key_466d = { 12 05 [2] 66 1d [2] 21 1f [2] 66 0e [2] 28 02 [2] 24 08 [2] 33 03 [2] 28 4d [2] 15 }

  condition:
    any of them
}