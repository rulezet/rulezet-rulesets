rule TTP_XOR_MULT_DOSStub_d710 {
  strings:
    $key_d710 = { 83 78 [2] f7 60 [2] b0 62 [2] f7 73 [2] b9 7f [2] b5 75 [2] a2 7e [2] b9 30 [2] 84 }

  condition:
    any of them
}