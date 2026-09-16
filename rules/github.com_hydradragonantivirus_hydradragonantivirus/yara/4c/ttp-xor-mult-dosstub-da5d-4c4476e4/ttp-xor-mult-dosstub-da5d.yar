rule TTP_XOR_MULT_DOSStub_da5d {
  strings:
    $key_da5d = { 8e 35 [2] fa 2d [2] bd 2f [2] fa 3e [2] b4 32 [2] b8 38 [2] af 33 [2] b4 7d [2] 89 }

  condition:
    any of them
}