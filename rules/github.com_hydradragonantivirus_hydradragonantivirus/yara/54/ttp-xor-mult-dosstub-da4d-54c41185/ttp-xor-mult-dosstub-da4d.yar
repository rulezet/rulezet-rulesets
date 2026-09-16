rule TTP_XOR_MULT_DOSStub_da4d {
  strings:
    $key_da4d = { 8e 25 [2] fa 3d [2] bd 3f [2] fa 2e [2] b4 22 [2] b8 28 [2] af 23 [2] b4 6d [2] 89 }

  condition:
    any of them
}