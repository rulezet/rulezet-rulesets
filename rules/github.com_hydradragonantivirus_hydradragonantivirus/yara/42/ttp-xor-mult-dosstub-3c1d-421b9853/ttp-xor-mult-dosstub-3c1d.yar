rule TTP_XOR_MULT_DOSStub_3c1d {
  strings:
    $key_3c1d = { 68 75 [2] 1c 6d [2] 5b 6f [2] 1c 7e [2] 52 72 [2] 5e 78 [2] 49 73 [2] 52 3d [2] 6f }

  condition:
    any of them
}