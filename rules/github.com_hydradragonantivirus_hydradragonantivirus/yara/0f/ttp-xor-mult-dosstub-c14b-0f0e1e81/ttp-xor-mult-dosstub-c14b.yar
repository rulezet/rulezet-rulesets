rule TTP_XOR_MULT_DOSStub_c14b {
  strings:
    $key_c14b = { 95 23 [2] e1 3b [2] a6 39 [2] e1 28 [2] af 24 [2] a3 2e [2] b4 25 [2] af 6b [2] 92 }

  condition:
    any of them
}