rule TTP_XOR_MULT_DOSStub_480d {
  strings:
    $key_480d = { 1c 65 [2] 68 7d [2] 2f 7f [2] 68 6e [2] 26 62 [2] 2a 68 [2] 3d 63 [2] 26 2d [2] 1b }

  condition:
    any of them
}