rule TTP_XOR_MULT_DOSStub_dae9 {
  strings:
    $key_dae9 = { 8e 81 [2] fa 99 [2] bd 9b [2] fa 8a [2] b4 86 [2] b8 8c [2] af 87 [2] b4 c9 [2] 89 }

  condition:
    any of them
}