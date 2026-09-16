rule TTP_XOR_MULT_DOSStub_da37 {
  strings:
    $key_da37 = { 8e 5f [2] fa 47 [2] bd 45 [2] fa 54 [2] b4 58 [2] b8 52 [2] af 59 [2] b4 17 [2] 89 }

  condition:
    any of them
}