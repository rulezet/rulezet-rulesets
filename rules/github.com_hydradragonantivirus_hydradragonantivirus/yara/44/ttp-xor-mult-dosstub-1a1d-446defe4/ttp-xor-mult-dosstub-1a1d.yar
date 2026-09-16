rule TTP_XOR_MULT_DOSStub_1a1d {
  strings:
    $key_1a1d = { 4e 75 [2] 3a 6d [2] 7d 6f [2] 3a 7e [2] 74 72 [2] 78 78 [2] 6f 73 [2] 74 3d [2] 49 }

  condition:
    any of them
}