rule TTP_XOR_MULT_DOSStub_da18 {
  strings:
    $key_da18 = { 8e 70 [2] fa 68 [2] bd 6a [2] fa 7b [2] b4 77 [2] b8 7d [2] af 76 [2] b4 38 [2] 89 }

  condition:
    any of them
}