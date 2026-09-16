rule TTP_XOR_MULT_DOSStub_001d {
  strings:
    $key_001d = { 54 75 [2] 20 6d [2] 67 6f [2] 20 7e [2] 6e 72 [2] 62 78 [2] 75 73 [2] 6e 3d [2] 53 }

  condition:
    any of them
}