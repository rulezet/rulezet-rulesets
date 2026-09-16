rule TTP_XOR_MULT_DOSStub_336d {
  strings:
    $key_336d = { 67 05 [2] 13 1d [2] 54 1f [2] 13 0e [2] 5d 02 [2] 51 08 [2] 46 03 [2] 5d 4d [2] 60 }

  condition:
    any of them
}