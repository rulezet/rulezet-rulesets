rule TTP_XOR_MULT_DOSStub_dd16 {
  strings:
    $key_dd16 = { 89 7e [2] fd 66 [2] ba 64 [2] fd 75 [2] b3 79 [2] bf 73 [2] a8 78 [2] b3 36 [2] 8e }

  condition:
    any of them
}