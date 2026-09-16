rule TTP_XOR_MULT_DOSStub_da63 {
  strings:
    $key_da63 = { 8e 0b [2] fa 13 [2] bd 11 [2] fa 00 [2] b4 0c [2] b8 06 [2] af 0d [2] b4 43 [2] 89 }

  condition:
    any of them
}