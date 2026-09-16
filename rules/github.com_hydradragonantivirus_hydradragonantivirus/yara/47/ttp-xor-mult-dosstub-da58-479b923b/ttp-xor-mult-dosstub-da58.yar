rule TTP_XOR_MULT_DOSStub_da58 {
  strings:
    $key_da58 = { 8e 30 [2] fa 28 [2] bd 2a [2] fa 3b [2] b4 37 [2] b8 3d [2] af 36 [2] b4 78 [2] 89 }

  condition:
    any of them
}