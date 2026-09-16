rule TTP_XOR_MULT_DOSStub_756d {
  strings:
    $key_756d = { 21 05 [2] 55 1d [2] 12 1f [2] 55 0e [2] 1b 02 [2] 17 08 [2] 00 03 [2] 1b 4d [2] 26 }

  condition:
    any of them
}