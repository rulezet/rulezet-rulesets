rule TTP_XOR_MULT_DOSStub_da2f {
  strings:
    $key_da2f = { 8e 47 [2] fa 5f [2] bd 5d [2] fa 4c [2] b4 40 [2] b8 4a [2] af 41 [2] b4 0f [2] 89 }

  condition:
    any of them
}