rule TTP_XOR_MULT_DOSStub_474d {
  strings:
    $key_474d = { 13 25 [2] 67 3d [2] 20 3f [2] 67 2e [2] 29 22 [2] 25 28 [2] 32 23 [2] 29 6d [2] 14 }

  condition:
    any of them
}