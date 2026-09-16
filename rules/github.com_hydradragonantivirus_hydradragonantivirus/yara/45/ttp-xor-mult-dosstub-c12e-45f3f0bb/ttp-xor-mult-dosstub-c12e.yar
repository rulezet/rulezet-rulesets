rule TTP_XOR_MULT_DOSStub_c12e {
  strings:
    $key_c12e = { 95 46 [2] e1 5e [2] a6 5c [2] e1 4d [2] af 41 [2] a3 4b [2] b4 40 [2] af 0e [2] 92 }

  condition:
    any of them
}