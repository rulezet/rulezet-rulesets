rule TTP_XOR_MULT_DOSStub_da3a {
  strings:
    $key_da3a = { 8e 52 [2] fa 4a [2] bd 48 [2] fa 59 [2] b4 55 [2] b8 5f [2] af 54 [2] b4 1a [2] 89 }

  condition:
    any of them
}