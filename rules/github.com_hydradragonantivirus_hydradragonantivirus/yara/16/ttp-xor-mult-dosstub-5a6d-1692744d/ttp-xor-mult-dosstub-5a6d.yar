rule TTP_XOR_MULT_DOSStub_5a6d {
  strings:
    $key_5a6d = { 0e 05 [2] 7a 1d [2] 3d 1f [2] 7a 0e [2] 34 02 [2] 38 08 [2] 2f 03 [2] 34 4d [2] 09 }

  condition:
    any of them
}