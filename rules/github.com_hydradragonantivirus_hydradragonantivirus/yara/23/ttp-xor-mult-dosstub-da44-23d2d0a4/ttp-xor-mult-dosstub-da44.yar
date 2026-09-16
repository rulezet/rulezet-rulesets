rule TTP_XOR_MULT_DOSStub_da44 {
  strings:
    $key_da44 = { 8e 2c [2] fa 34 [2] bd 36 [2] fa 27 [2] b4 2b [2] b8 21 [2] af 2a [2] b4 64 [2] 89 }

  condition:
    any of them
}