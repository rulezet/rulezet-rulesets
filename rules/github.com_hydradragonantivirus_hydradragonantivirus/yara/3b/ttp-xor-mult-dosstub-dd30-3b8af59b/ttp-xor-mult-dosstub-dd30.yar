rule TTP_XOR_MULT_DOSStub_dd30 {
  strings:
    $key_dd30 = { 89 58 [2] fd 40 [2] ba 42 [2] fd 53 [2] b3 5f [2] bf 55 [2] a8 5e [2] b3 10 [2] 8e }

  condition:
    any of them
}