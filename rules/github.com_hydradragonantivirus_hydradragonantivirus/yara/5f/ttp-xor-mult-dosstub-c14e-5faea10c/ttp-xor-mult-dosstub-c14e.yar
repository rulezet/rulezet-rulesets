rule TTP_XOR_MULT_DOSStub_c14e {
  strings:
    $key_c14e = { 95 26 [2] e1 3e [2] a6 3c [2] e1 2d [2] af 21 [2] a3 2b [2] b4 20 [2] af 6e [2] 92 }

  condition:
    any of them
}