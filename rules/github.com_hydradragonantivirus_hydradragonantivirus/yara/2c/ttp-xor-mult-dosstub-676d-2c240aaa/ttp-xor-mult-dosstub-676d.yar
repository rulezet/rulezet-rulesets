rule TTP_XOR_MULT_DOSStub_676d {
  strings:
    $key_676d = { 33 05 [2] 47 1d [2] 00 1f [2] 47 0e [2] 09 02 [2] 05 08 [2] 12 03 [2] 09 4d [2] 34 }

  condition:
    any of them
}