rule TTP_XOR_MULT_DOSStub_266d {
  strings:
    $key_266d = { 72 05 [2] 06 1d [2] 41 1f [2] 06 0e [2] 48 02 [2] 44 08 [2] 53 03 [2] 48 4d [2] 75 }

  condition:
    any of them
}