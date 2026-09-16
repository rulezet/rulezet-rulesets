rule TTP_XOR_MULT_DOSStub_da64 {
  strings:
    $key_da64 = { 8e 0c [2] fa 14 [2] bd 16 [2] fa 07 [2] b4 0b [2] b8 01 [2] af 0a [2] b4 44 [2] 89 }

  condition:
    any of them
}