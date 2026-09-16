rule TTP_XOR_MULT_DOSStub_da28 {
  strings:
    $key_da28 = { 8e 40 [2] fa 58 [2] bd 5a [2] fa 4b [2] b4 47 [2] b8 4d [2] af 46 [2] b4 08 [2] 89 }

  condition:
    any of them
}