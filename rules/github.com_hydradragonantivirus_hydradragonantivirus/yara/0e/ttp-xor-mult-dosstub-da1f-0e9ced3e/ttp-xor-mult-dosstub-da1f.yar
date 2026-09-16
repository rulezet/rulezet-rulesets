rule TTP_XOR_MULT_DOSStub_da1f {
  strings:
    $key_da1f = { 8e 77 [2] fa 6f [2] bd 6d [2] fa 7c [2] b4 70 [2] b8 7a [2] af 71 [2] b4 3f [2] 89 }

  condition:
    any of them
}