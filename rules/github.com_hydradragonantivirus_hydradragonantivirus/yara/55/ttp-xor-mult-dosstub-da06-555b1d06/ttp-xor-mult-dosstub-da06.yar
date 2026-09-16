rule TTP_XOR_MULT_DOSStub_da06 {
  strings:
    $key_da06 = { 8e 6e [2] fa 76 [2] bd 74 [2] fa 65 [2] b4 69 [2] b8 63 [2] af 68 [2] b4 26 [2] 89 }

  condition:
    any of them
}