rule TTP_XOR_MULT_DOSStub_da45 {
  strings:
    $key_da45 = { 8e 2d [2] fa 35 [2] bd 37 [2] fa 26 [2] b4 2a [2] b8 20 [2] af 2b [2] b4 65 [2] 89 }

  condition:
    any of them
}