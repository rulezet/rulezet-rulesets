rule TTP_XOR_MULT_DOSStub_356d {
  strings:
    $key_356d = { 61 05 [2] 15 1d [2] 52 1f [2] 15 0e [2] 5b 02 [2] 57 08 [2] 40 03 [2] 5b 4d [2] 66 }

  condition:
    any of them
}