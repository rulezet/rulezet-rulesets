rule TTP_XOR_MULT_DOSStub_476d {
  strings:
    $key_476d = { 13 05 [2] 67 1d [2] 20 1f [2] 67 0e [2] 29 02 [2] 25 08 [2] 32 03 [2] 29 4d [2] 14 }

  condition:
    any of them
}