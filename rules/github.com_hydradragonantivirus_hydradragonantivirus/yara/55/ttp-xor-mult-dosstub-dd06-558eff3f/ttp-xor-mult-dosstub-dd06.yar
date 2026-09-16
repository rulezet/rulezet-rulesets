rule TTP_XOR_MULT_DOSStub_dd06 {
  strings:
    $key_dd06 = { 89 6e [2] fd 76 [2] ba 74 [2] fd 65 [2] b3 69 [2] bf 63 [2] a8 68 [2] b3 26 [2] 8e }

  condition:
    any of them
}