rule TTP_XOR_MULT_DOSStub_c15b {
  strings:
    $key_c15b = { 95 33 [2] e1 2b [2] a6 29 [2] e1 38 [2] af 34 [2] a3 3e [2] b4 35 [2] af 7b [2] 92 }

  condition:
    any of them
}