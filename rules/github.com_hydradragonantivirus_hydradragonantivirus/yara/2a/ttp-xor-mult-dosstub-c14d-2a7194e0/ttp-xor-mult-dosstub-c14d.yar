rule TTP_XOR_MULT_DOSStub_c14d {
  strings:
    $key_c14d = { 95 25 [2] e1 3d [2] a6 3f [2] e1 2e [2] af 22 [2] a3 28 [2] b4 23 [2] af 6d [2] 92 }

  condition:
    any of them
}