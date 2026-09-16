rule TTP_XOR_MULT_DOSStub_dd36 {
  strings:
    $key_dd36 = { 89 5e [2] fd 46 [2] ba 44 [2] fd 55 [2] b3 59 [2] bf 53 [2] a8 58 [2] b3 16 [2] 8e }

  condition:
    any of them
}