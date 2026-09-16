rule TTP_XOR_MULT_DOSStub_da30 {
  strings:
    $key_da30 = { 8e 58 [2] fa 40 [2] bd 42 [2] fa 53 [2] b4 5f [2] b8 55 [2] af 5e [2] b4 10 [2] 89 }

  condition:
    any of them
}