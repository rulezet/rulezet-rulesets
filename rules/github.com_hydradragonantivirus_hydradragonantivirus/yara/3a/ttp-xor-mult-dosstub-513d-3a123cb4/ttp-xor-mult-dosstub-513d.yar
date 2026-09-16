rule TTP_XOR_MULT_DOSStub_513d {
  strings:
    $key_513d = { 05 55 [2] 71 4d [2] 36 4f [2] 71 5e [2] 3f 52 [2] 33 58 [2] 24 53 [2] 3f 1d [2] 02 }

  condition:
    any of them
}