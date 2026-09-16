rule TTP_XOR_MULT_DOSStub_0d3d {
  strings:
    $key_0d3d = { 59 55 [2] 2d 4d [2] 6a 4f [2] 2d 5e [2] 63 52 [2] 6f 58 [2] 78 53 [2] 63 1d [2] 5e }

  condition:
    any of them
}