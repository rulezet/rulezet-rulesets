rule TTP_XOR_MULT_DOSStub_560d {
  strings:
    $key_560d = { 02 65 [2] 76 7d [2] 31 7f [2] 76 6e [2] 38 62 [2] 34 68 [2] 23 63 [2] 38 2d [2] 05 }

  condition:
    any of them
}