rule TTP_XOR_MULT_DOSStub_da0f {
  strings:
    $key_da0f = { 8e 67 [2] fa 7f [2] bd 7d [2] fa 6c [2] b4 60 [2] b8 6a [2] af 61 [2] b4 2f [2] 89 }

  condition:
    any of them
}