rule TTP_XOR_MULT_DOSStub_dd17 {
  strings:
    $key_dd17 = { 89 7f [2] fd 67 [2] ba 65 [2] fd 74 [2] b3 78 [2] bf 72 [2] a8 79 [2] b3 37 [2] 8e }

  condition:
    any of them
}