rule TTP_XOR_MULT_DOSStub_086d {
  strings:
    $key_086d = { 5c 05 [2] 28 1d [2] 6f 1f [2] 28 0e [2] 66 02 [2] 6a 08 [2] 7d 03 [2] 66 4d [2] 5b }

  condition:
    any of them
}