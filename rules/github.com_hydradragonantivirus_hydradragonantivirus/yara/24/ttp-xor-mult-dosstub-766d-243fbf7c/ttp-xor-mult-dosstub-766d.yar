rule TTP_XOR_MULT_DOSStub_766d {
  strings:
    $key_766d = { 22 05 [2] 56 1d [2] 11 1f [2] 56 0e [2] 18 02 [2] 14 08 [2] 03 03 [2] 18 4d [2] 25 }

  condition:
    any of them
}