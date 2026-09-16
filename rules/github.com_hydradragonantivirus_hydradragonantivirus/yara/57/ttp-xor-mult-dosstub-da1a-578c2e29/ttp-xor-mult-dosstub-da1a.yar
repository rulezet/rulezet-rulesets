rule TTP_XOR_MULT_DOSStub_da1a {
  strings:
    $key_da1a = { 8e 72 [2] fa 6a [2] bd 68 [2] fa 79 [2] b4 75 [2] b8 7f [2] af 74 [2] b4 3a [2] 89 }

  condition:
    any of them
}