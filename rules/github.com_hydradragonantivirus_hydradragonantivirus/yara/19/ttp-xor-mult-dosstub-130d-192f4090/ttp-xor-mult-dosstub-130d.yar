rule TTP_XOR_MULT_DOSStub_130d {
  strings:
    $key_130d = { 47 65 [2] 33 7d [2] 74 7f [2] 33 6e [2] 7d 62 [2] 71 68 [2] 66 63 [2] 7d 2d [2] 40 }

  condition:
    any of them
}