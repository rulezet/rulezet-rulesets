rule TTP_XOR_MULT_DOSStub_c15c {
  strings:
    $key_c15c = { 95 34 [2] e1 2c [2] a6 2e [2] e1 3f [2] af 33 [2] a3 39 [2] b4 32 [2] af 7c [2] 92 }

  condition:
    any of them
}