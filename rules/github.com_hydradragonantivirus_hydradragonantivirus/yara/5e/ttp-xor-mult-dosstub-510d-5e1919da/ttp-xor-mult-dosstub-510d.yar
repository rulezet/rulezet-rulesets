rule TTP_XOR_MULT_DOSStub_510d {
  strings:
    $key_510d = { 05 65 [2] 71 7d [2] 36 7f [2] 71 6e [2] 3f 62 [2] 33 68 [2] 24 63 [2] 3f 2d [2] 02 }

  condition:
    any of them
}