rule TTP_XOR_MULT_DOSStub_dae2 {
  strings:
    $key_dae2 = { 8e 8a [2] fa 92 [2] bd 90 [2] fa 81 [2] b4 8d [2] b8 87 [2] af 8c [2] b4 c2 [2] 89 }

  condition:
    any of them
}