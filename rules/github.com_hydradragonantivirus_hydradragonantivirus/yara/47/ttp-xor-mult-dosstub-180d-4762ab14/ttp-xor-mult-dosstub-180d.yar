rule TTP_XOR_MULT_DOSStub_180d {
  strings:
    $key_180d = { 4c 65 [2] 38 7d [2] 7f 7f [2] 38 6e [2] 76 62 [2] 7a 68 [2] 6d 63 [2] 76 2d [2] 4b }

  condition:
    any of them
}