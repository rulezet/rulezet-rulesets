rule TTP_XOR_MULT_DOSStub_436d {
  strings:
    $key_436d = { 17 05 [2] 63 1d [2] 24 1f [2] 63 0e [2] 2d 02 [2] 21 08 [2] 36 03 [2] 2d 4d [2] 10 }

  condition:
    any of them
}