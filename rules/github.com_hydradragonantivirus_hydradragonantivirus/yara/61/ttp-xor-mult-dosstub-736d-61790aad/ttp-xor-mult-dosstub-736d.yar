rule TTP_XOR_MULT_DOSStub_736d {
  strings:
    $key_736d = { 27 05 [2] 53 1d [2] 14 1f [2] 53 0e [2] 1d 02 [2] 11 08 [2] 06 03 [2] 1d 4d [2] 20 }

  condition:
    any of them
}