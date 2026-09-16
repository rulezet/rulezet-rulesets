rule TTP_XOR_MULT_DOSStub_dd26 {
  strings:
    $key_dd26 = { 89 4e [2] fd 56 [2] ba 54 [2] fd 45 [2] b3 49 [2] bf 43 [2] a8 48 [2] b3 06 [2] 8e }

  condition:
    any of them
}