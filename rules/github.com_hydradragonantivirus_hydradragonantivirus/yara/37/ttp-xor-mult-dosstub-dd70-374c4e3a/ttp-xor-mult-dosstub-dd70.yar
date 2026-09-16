rule TTP_XOR_MULT_DOSStub_dd70 {
  strings:
    $key_dd70 = { 89 18 [2] fd 00 [2] ba 02 [2] fd 13 [2] b3 1f [2] bf 15 [2] a8 1e [2] b3 50 [2] 8e }

  condition:
    any of them
}