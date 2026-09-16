rule TTP_XOR_MULT_DOSStub_724d {
  strings:
    $key_724d = { 26 25 [2] 52 3d [2] 15 3f [2] 52 2e [2] 1c 22 [2] 10 28 [2] 07 23 [2] 1c 6d [2] 21 }

  condition:
    any of them
}