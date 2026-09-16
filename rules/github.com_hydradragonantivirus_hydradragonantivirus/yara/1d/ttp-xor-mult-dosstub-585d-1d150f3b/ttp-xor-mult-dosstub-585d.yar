rule TTP_XOR_MULT_DOSStub_585d {
  strings:
    $key_585d = { 0c 35 [2] 78 2d [2] 3f 2f [2] 78 3e [2] 36 32 [2] 3a 38 [2] 2d 33 [2] 36 7d [2] 0b }

  condition:
    any of them
}