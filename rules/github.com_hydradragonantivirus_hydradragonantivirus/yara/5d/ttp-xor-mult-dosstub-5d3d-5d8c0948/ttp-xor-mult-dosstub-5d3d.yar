rule TTP_XOR_MULT_DOSStub_5d3d {
  strings:
    $key_5d3d = { 09 55 [2] 7d 4d [2] 3a 4f [2] 7d 5e [2] 33 52 [2] 3f 58 [2] 28 53 [2] 33 1d [2] 0e }

  condition:
    any of them
}