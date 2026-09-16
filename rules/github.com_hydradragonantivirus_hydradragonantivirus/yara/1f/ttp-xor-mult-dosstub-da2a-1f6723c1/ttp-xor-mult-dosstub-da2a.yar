rule TTP_XOR_MULT_DOSStub_da2a {
  strings:
    $key_da2a = { 8e 42 [2] fa 5a [2] bd 58 [2] fa 49 [2] b4 45 [2] b8 4f [2] af 44 [2] b4 0a [2] 89 }

  condition:
    any of them
}