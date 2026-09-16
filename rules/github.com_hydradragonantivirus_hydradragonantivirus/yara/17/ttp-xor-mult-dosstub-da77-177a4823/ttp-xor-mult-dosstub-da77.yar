rule TTP_XOR_MULT_DOSStub_da77 {
  strings:
    $key_da77 = { 8e 1f [2] fa 07 [2] bd 05 [2] fa 14 [2] b4 18 [2] b8 12 [2] af 19 [2] b4 57 [2] 89 }

  condition:
    any of them
}