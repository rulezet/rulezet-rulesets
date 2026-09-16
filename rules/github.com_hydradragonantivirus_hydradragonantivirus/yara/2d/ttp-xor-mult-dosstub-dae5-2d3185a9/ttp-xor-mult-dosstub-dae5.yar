rule TTP_XOR_MULT_DOSStub_dae5 {
  strings:
    $key_dae5 = { 8e 8d [2] fa 95 [2] bd 97 [2] fa 86 [2] b4 8a [2] b8 80 [2] af 8b [2] b4 c5 [2] 89 }

  condition:
    any of them
}