rule TTP_XOR_MULT_DOSStub_da11 {
  strings:
    $key_da11 = { 8e 79 [2] fa 61 [2] bd 63 [2] fa 72 [2] b4 7e [2] b8 74 [2] af 7f [2] b4 31 [2] 89 }

  condition:
    any of them
}