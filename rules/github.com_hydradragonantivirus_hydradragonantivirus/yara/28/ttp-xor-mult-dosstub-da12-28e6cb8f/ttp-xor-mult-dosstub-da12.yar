rule TTP_XOR_MULT_DOSStub_da12 {
  strings:
    $key_da12 = { 8e 7a [2] fa 62 [2] bd 60 [2] fa 71 [2] b4 7d [2] b8 77 [2] af 7c [2] b4 32 [2] 89 }

  condition:
    any of them
}