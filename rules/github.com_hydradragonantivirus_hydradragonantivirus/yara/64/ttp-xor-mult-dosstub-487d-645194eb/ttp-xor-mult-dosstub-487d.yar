rule TTP_XOR_MULT_DOSStub_487d {
  strings:
    $key_487d = { 1c 15 [2] 68 0d [2] 2f 0f [2] 68 1e [2] 26 12 [2] 2a 18 [2] 3d 13 [2] 26 5d [2] 1b }

  condition:
    any of them
}