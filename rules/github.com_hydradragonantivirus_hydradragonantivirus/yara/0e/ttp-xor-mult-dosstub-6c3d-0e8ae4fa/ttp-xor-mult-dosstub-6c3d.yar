rule TTP_XOR_MULT_DOSStub_6c3d {
  strings:
    $key_6c3d = { 38 55 [2] 4c 4d [2] 0b 4f [2] 4c 5e [2] 02 52 [2] 0e 58 [2] 19 53 [2] 02 1d [2] 3f }

  condition:
    any of them
}