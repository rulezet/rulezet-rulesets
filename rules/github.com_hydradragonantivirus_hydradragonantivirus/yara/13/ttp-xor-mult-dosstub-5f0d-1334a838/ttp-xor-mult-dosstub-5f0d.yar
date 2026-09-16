rule TTP_XOR_MULT_DOSStub_5f0d {
  strings:
    $key_5f0d = { 0b 65 [2] 7f 7d [2] 38 7f [2] 7f 6e [2] 31 62 [2] 3d 68 [2] 2a 63 [2] 31 2d [2] 0c }

  condition:
    any of them
}