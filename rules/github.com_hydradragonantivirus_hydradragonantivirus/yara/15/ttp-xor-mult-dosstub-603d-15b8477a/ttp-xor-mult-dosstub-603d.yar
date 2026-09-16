rule TTP_XOR_MULT_DOSStub_603d {
  strings:
    $key_603d = { 34 55 [2] 40 4d [2] 07 4f [2] 40 5e [2] 0e 52 [2] 02 58 [2] 15 53 [2] 0e 1d [2] 33 }

  condition:
    any of them
}