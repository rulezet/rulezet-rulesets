rule TTP_XOR_MULT_DOSStub_c152 {
  strings:
    $key_c152 = { 95 3a [2] e1 22 [2] a6 20 [2] e1 31 [2] af 3d [2] a3 37 [2] b4 3c [2] af 72 [2] 92 }

  condition:
    any of them
}