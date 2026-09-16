rule TTP_XOR_MULT_DOSStub_da27 {
  strings:
    $key_da27 = { 8e 4f [2] fa 57 [2] bd 55 [2] fa 44 [2] b4 48 [2] b8 42 [2] af 49 [2] b4 07 [2] 89 }

  condition:
    any of them
}