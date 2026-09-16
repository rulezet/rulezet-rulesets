rule TTP_XOR_MULT_DOSStub_1a3d {
  strings:
    $key_1a3d = { 4e 55 [2] 3a 4d [2] 7d 4f [2] 3a 5e [2] 74 52 [2] 78 58 [2] 6f 53 [2] 74 1d [2] 49 }

  condition:
    any of them
}