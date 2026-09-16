rule TTP_XOR_MULT_DOSStub_600d {
  strings:
    $key_600d = { 34 65 [2] 40 7d [2] 07 7f [2] 40 6e [2] 0e 62 [2] 02 68 [2] 15 63 [2] 0e 2d [2] 33 }

  condition:
    any of them
}