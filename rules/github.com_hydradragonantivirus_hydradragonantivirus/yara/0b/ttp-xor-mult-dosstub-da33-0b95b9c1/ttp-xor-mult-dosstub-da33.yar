rule TTP_XOR_MULT_DOSStub_da33 {
  strings:
    $key_da33 = { 8e 5b [2] fa 43 [2] bd 41 [2] fa 50 [2] b4 5c [2] b8 56 [2] af 5d [2] b4 13 [2] 89 }

  condition:
    any of them
}