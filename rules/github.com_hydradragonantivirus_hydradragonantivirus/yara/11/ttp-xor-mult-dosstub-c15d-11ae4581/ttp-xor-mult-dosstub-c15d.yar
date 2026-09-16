rule TTP_XOR_MULT_DOSStub_c15d {
  strings:
    $key_c15d = { 95 35 [2] e1 2d [2] a6 2f [2] e1 3e [2] af 32 [2] a3 38 [2] b4 33 [2] af 7d [2] 92 }

  condition:
    any of them
}