rule TTP_XOR_MULT_DOSStub_c1ee {
  strings:
    $key_c1ee = { 95 86 [2] e1 9e [2] a6 9c [2] e1 8d [2] af 81 [2] a3 8b [2] b4 80 [2] af ce [2] 92 }

  condition:
    any of them
}