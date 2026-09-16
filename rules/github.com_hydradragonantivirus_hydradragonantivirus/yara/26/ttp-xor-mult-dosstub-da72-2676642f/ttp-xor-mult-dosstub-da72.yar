rule TTP_XOR_MULT_DOSStub_da72 {
  strings:
    $key_da72 = { 8e 1a [2] fa 02 [2] bd 00 [2] fa 11 [2] b4 1d [2] b8 17 [2] af 1c [2] b4 52 [2] 89 }

  condition:
    any of them
}