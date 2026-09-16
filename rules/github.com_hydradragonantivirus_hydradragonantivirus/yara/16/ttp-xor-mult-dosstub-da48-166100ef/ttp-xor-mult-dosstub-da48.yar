rule TTP_XOR_MULT_DOSStub_da48 {
  strings:
    $key_da48 = { 8e 20 [2] fa 38 [2] bd 3a [2] fa 2b [2] b4 27 [2] b8 2d [2] af 26 [2] b4 68 [2] 89 }

  condition:
    any of them
}