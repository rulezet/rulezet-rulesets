rule TTP_XOR_MULT_DOSStub_606d {
  strings:
    $key_606d = { 34 05 [2] 40 1d [2] 07 1f [2] 40 0e [2] 0e 02 [2] 02 08 [2] 15 03 [2] 0e 4d [2] 33 }

  condition:
    any of them
}