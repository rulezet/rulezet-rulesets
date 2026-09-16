rule TTP_XOR_MULT_DOSStub_470d {
  strings:
    $key_470d = { 13 65 [2] 67 7d [2] 20 7f [2] 67 6e [2] 29 62 [2] 25 68 [2] 32 63 [2] 29 2d [2] 14 }

  condition:
    any of them
}