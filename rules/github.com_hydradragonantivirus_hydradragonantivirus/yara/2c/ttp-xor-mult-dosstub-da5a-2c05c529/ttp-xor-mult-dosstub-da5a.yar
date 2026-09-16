rule TTP_XOR_MULT_DOSStub_da5a {
  strings:
    $key_da5a = { 8e 32 [2] fa 2a [2] bd 28 [2] fa 39 [2] b4 35 [2] b8 3f [2] af 34 [2] b4 7a [2] 89 }

  condition:
    any of them
}