rule TTP_XOR_MULT_DOSStub_da49 {
  strings:
    $key_da49 = { 8e 21 [2] fa 39 [2] bd 3b [2] fa 2a [2] b4 26 [2] b8 2c [2] af 27 [2] b4 69 [2] 89 }

  condition:
    any of them
}