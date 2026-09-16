rule TTP_XOR_MULT_DOSStub_da7f {
  strings:
    $key_da7f = { 8e 17 [2] fa 0f [2] bd 0d [2] fa 1c [2] b4 10 [2] b8 1a [2] af 11 [2] b4 5f [2] 89 }

  condition:
    any of them
}