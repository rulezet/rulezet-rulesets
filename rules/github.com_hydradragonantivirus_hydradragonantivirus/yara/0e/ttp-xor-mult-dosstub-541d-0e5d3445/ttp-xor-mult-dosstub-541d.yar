rule TTP_XOR_MULT_DOSStub_541d {
  strings:
    $key_541d = { 00 75 [2] 74 6d [2] 33 6f [2] 74 7e [2] 3a 72 [2] 36 78 [2] 21 73 [2] 3a 3d [2] 07 }

  condition:
    any of them
}