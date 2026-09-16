rule TTP_XOR_MULT_DOSStub_dd31 {
  strings:
    $key_dd31 = { 89 59 [2] fd 41 [2] ba 43 [2] fd 52 [2] b3 5e [2] bf 54 [2] a8 5f [2] b3 11 [2] 8e }

  condition:
    any of them
}