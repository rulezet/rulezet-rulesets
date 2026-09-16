rule TTP_XOR_MULT_DOSStub_dd76 {
  strings:
    $key_dd76 = { 89 1e [2] fd 06 [2] ba 04 [2] fd 15 [2] b3 19 [2] bf 13 [2] a8 18 [2] b3 56 [2] 8e }

  condition:
    any of them
}