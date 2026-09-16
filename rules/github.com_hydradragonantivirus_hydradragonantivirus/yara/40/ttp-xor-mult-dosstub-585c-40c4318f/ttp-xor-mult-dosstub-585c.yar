rule TTP_XOR_MULT_DOSStub_585c {
  strings:
    $key_585c = { 0c 34 [2] 78 2c [2] 3f 2e [2] 78 3f [2] 36 33 [2] 3a 39 [2] 2d 32 [2] 36 7c [2] 0b }

  condition:
    any of them
}