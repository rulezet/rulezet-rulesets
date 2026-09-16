rule TTP_XOR_MULT_DOSStub_1a0d {
  strings:
    $key_1a0d = { 4e 65 [2] 3a 7d [2] 7d 7f [2] 3a 6e [2] 74 62 [2] 78 68 [2] 6f 63 [2] 74 2d [2] 49 }

  condition:
    any of them
}