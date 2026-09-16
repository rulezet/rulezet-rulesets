rule TTP_XOR_MULT_DOSStub_697d {
  strings:
    $key_697d = { 3d 15 [2] 49 0d [2] 0e 0f [2] 49 1e [2] 07 12 [2] 0b 18 [2] 1c 13 [2] 07 5d [2] 3a }

  condition:
    any of them
}