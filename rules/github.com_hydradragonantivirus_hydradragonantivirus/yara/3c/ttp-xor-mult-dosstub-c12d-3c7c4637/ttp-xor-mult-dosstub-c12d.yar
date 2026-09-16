rule TTP_XOR_MULT_DOSStub_c12d {
  strings:
    $key_c12d = { 95 45 [2] e1 5d [2] a6 5f [2] e1 4e [2] af 42 [2] a3 48 [2] b4 43 [2] af 0d [2] 92 }

  condition:
    any of them
}