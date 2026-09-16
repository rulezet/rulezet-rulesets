rule TTP_XOR_MULT_DOSStub_da05 {
  strings:
    $key_da05 = { 8e 6d [2] fa 75 [2] bd 77 [2] fa 66 [2] b4 6a [2] b8 60 [2] af 6b [2] b4 25 [2] 89 }

  condition:
    any of them
}