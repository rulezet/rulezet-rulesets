rule TTP_XOR_MULT_DOSStub_da66 {
  strings:
    $key_da66 = { 8e 0e [2] fa 16 [2] bd 14 [2] fa 05 [2] b4 09 [2] b8 03 [2] af 08 [2] b4 46 [2] 89 }

  condition:
    any of them
}