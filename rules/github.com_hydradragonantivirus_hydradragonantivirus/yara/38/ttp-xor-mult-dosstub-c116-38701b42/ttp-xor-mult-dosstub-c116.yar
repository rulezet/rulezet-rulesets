rule TTP_XOR_MULT_DOSStub_c116 {
  strings:
    $key_c116 = { 95 7e [2] e1 66 [2] a6 64 [2] e1 75 [2] af 79 [2] a3 73 [2] b4 78 [2] af 36 [2] 92 }

  condition:
    any of them
}