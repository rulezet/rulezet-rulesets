rule TTP_XOR_MULT_DOSStub_201d {
  strings:
    $key_201d = { 74 75 [2] 00 6d [2] 47 6f [2] 00 7e [2] 4e 72 [2] 42 78 [2] 55 73 [2] 4e 3d [2] 73 }

  condition:
    any of them
}