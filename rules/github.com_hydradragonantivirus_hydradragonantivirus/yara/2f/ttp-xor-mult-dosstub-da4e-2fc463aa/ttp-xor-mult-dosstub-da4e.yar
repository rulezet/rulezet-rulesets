rule TTP_XOR_MULT_DOSStub_da4e {
  strings:
    $key_da4e = { 8e 26 [2] fa 3e [2] bd 3c [2] fa 2d [2] b4 21 [2] b8 2b [2] af 20 [2] b4 6e [2] 89 }

  condition:
    any of them
}