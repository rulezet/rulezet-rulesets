rule TTP_XOR_MULT_DOSStub_540d {
  strings:
    $key_540d = { 00 65 [2] 74 7d [2] 33 7f [2] 74 6e [2] 3a 62 [2] 36 68 [2] 21 63 [2] 3a 2d [2] 07 }

  condition:
    any of them
}